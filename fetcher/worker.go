package fetcher

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/openpaily/paily-fetch/node"
)

const defaultFetchUA = "clash-verge/v1.0.0"

// downloadJob is the unit of work sent to HTTP workers.
type downloadJob struct {
	source Source
}

// downloadResult carries all collected response bodies (or error) for a source.
type downloadResult struct {
	source Source
	bodies [][]byte // one entry per successfully fetched sub-URL
	err    error
}

// processJob carries one or more response bodies to CPU-bound parse workers.
// For "node" sources bodies is nil; the parse worker reads source.Content directly.
type processJob struct {
	source Source
	bodies [][]byte
}

// processResult carries parsed nodes back from parse workers.
type processResult struct {
	source Source
	nodes  []*node.ProxyNode
	err    error
}

// proxyLinkRe matches non-HTTP proxy-protocol URLs embedded anywhere in text.
// Written as a broad alternation so new proxy protocols are handled by updating here.
var proxyLinkRe = regexp.MustCompile(
	`(?:vmess|vless|trojan|ssr?|hysteria2?|hy2|tuic|wg|wireguard|socks5?|anytls|mierus?|sudoku)://[^ \t\r\n<>"'\x60\x00-\x1f]+`,
)

// httpLinkRe matches http and https URLs embedded anywhere in text.
var httpLinkRe = regexp.MustCompile(`https?://[^ \t\r\n<>"'\x60\x00-\x1f]+`)

// runHTTPWorkers launches concurrency HTTP workers.
// Each worker handles one source job: it resolves all content lines (handling expr:,
// exprdate:, extract: prefixes), fetches all resolved URLs, and emits one
// downloadResult carrying all collected response bodies.
func runHTTPWorkers(
	ctx context.Context,
	jobs <-chan downloadJob,
	concurrency int,
	downloadTimeout time.Duration,
	fetchUA string,
) <-chan downloadResult {
	out := make(chan downloadResult, concurrency*2)
	var wg sync.WaitGroup
	hc := &http.Client{Timeout: downloadTimeout}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				bodies, err := fetchSourceBodies(ctx, hc, fetchUA, job.source)
				select {
				case out <- downloadResult{source: job.source, bodies: bodies, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// fetchSourceBodies resolves all lines in src.Content and fetches each resolved URL.
//
// Supported line prefixes:
//   - expr:      evaluate as an expr-lang expression returning a URL string
//   - exprdate:  expand {y}/{m}/{d} date placeholders in a URL template
//   - extract:   fetch the URL, scan body for http(s) links (added to fetch list)
//     and proxy-protocol links (bundled as a URL-list inline body)
//   - (default)  use the line as a URL directly
//
// Partial failures (some lines fail, others succeed) are logged but not fatal.
// An error is returned only when every sub-URL fails.
func fetchSourceBodies(ctx context.Context, hc *http.Client, fetchUA string, src Source) ([][]byte, error) {
	lines := splitNonEmptyLines(src.Content)

	var fetchURLs []string
	var inlineBodies [][]byte // pre-assembled bodies from extract: proxy links

	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "expr:"):
			u, err := evalContent(line)
			if err != nil {
				log.Printf("[fetcher] source %s expr %q: %v", src.ID, line, err)
				continue
			}
			fetchURLs = append(fetchURLs, u)

		case strings.HasPrefix(line, "exprdate:"):
			u, err := evalExprDate(line)
			if err != nil {
				log.Printf("[fetcher] source %s exprdate %q: %v", src.ID, line, err)
				continue
			}
			fetchURLs = append(fetchURLs, u)

		case strings.HasPrefix(line, "extract:"):
			rawURL := strings.TrimSpace(line[len("extract:"):])
			httpURLs, proxyBody, err := extractURLsFromRemote(ctx, hc, fetchUA, rawURL)
			if err != nil {
				log.Printf("[fetcher] source %s extract %q: %v", src.ID, rawURL, err)
				continue
			}
			fetchURLs = append(fetchURLs, httpURLs...)
			if len(proxyBody) > 0 {
				inlineBodies = append(inlineBodies, proxyBody)
			}

		default:
			fetchURLs = append(fetchURLs, line)
		}
	}

	totalAttempts := len(inlineBodies) + len(fetchURLs)
	bodies := make([][]byte, 0, totalAttempts)
	bodies = append(bodies, inlineBodies...)

	for _, u := range fetchURLs {
		body, err := downloadURL(ctx, hc, fetchUA, u)
		if err != nil {
			log.Printf("[fetcher] source %s fetch %q: %v", src.ID, u, err)
			continue
		}
		bodies = append(bodies, body)
	}

	if len(bodies) == 0 && totalAttempts > 0 {
		return nil, fmt.Errorf("all %d fetch attempt(s) failed", totalAttempts)
	}
	return bodies, nil
}

// extractURLsFromRemote fetches rawURL and scans the response body for URLs:
//   - http(s) URLs are returned as httpURLs (to be fetched as subscriptions).
//   - proxy-protocol URLs are joined with "\n" and returned as proxyBody
//     (treated as a URL-list body by the parse stage).
func extractURLsFromRemote(ctx context.Context, hc *http.Client, fetchUA, rawURL string) (httpURLs []string, proxyBody []byte, err error) {
	body, fetchErr := downloadURL(ctx, hc, fetchUA, rawURL)
	if fetchErr != nil {
		return nil, nil, fetchErr
	}
	text := string(body)
	seen := make(map[string]bool)

	for _, m := range httpLinkRe.FindAllString(text, -1) {
		m = strings.TrimRight(m, ".,;:)")
		if !seen[m] {
			seen[m] = true
			httpURLs = append(httpURLs, m)
		}
	}
	var proxyLinks []string
	for _, m := range proxyLinkRe.FindAllString(text, -1) {
		m = strings.TrimRight(m, ".,;:)")
		if !seen[m] {
			seen[m] = true
			proxyLinks = append(proxyLinks, m)
		}
	}
	if len(proxyLinks) > 0 {
		proxyBody = []byte(strings.Join(proxyLinks, "\n"))
	}
	return httpURLs, proxyBody, nil
}

// splitNonEmptyLines splits s on newlines and returns trimmed, non-empty segments.
func splitNonEmptyLines(s string) []string {
	raw := strings.Split(s, "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// DownloadURL fetches a URL with the default User-Agent using a 30 s client.
// Exported for use by external tools (e.g. cmd/cli).
func DownloadURL(ctx context.Context, rawURL string) ([]byte, error) {
	hc := &http.Client{Timeout: 30 * time.Second}
	return downloadURL(ctx, hc, defaultFetchUA, rawURL)
}

// downloadURL fetches a URL with the supplied User-Agent.
func downloadURL(ctx context.Context, hc *http.Client, fetchUA, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if fetchUA != "" {
		req.Header.Set("User-Agent", fetchUA)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // 32 MB cap
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

// runParseWorkers launches concurrency parse workers that consume processJobs and emit processResults.
func runParseWorkers(
	ctx context.Context,
	jobs <-chan processJob,
	concurrency int,
) <-chan processResult {
	out := make(chan processResult, concurrency*2)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				nodes, err := parseSourceBodies(job.source, job.bodies)
				if err != nil {
					log.Printf("[fetcher] parse source %s (%s): %v", job.source.ID, job.source.Identifier, err)
				}

				var validNodes []*node.ProxyNode
				for _, n := range nodes {
					if n.Validate() == nil {
						validNodes = append(validNodes, n)
					}
				}

				select {
				case out <- processResult{source: job.source, nodes: validNodes, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// parseSourceBodies parses all bodies for a source and returns the aggregated node list.
// For "node" sources, source.Content is used directly (bodies is ignored).
// Partial body failures are logged but not fatal; an error is returned only when
// every body fails.
func parseSourceBodies(src Source, bodies [][]byte) ([]*node.ProxyNode, error) {
	if src.Type == "node" {
		return ParseNodeSourceContent(src.Content)
	}
	var all []*node.ProxyNode
	var lastErr error
	failCount := 0
	for _, body := range bodies {
		nodes, err := ParseSubscriptionBody(body)
		if err != nil {
			log.Printf("[fetcher] parse body for source %s: %v", src.ID, err)
			lastErr = err
			failCount++
			continue
		}
		all = append(all, nodes...)
	}
	if failCount == len(bodies) && len(bodies) > 0 {
		return nil, lastErr
	}
	return all, nil
}
