package input

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/openpaily/paily-fetch/node"
)

// ParseMixedLinks parses a slice of proxy link strings and returns all successfully
// parsed ProxyNodes. Links that cannot be parsed are logged with [SKIP][input/links]
// and skipped. A non-nil error is never returned; the error return exists for
// interface uniformity.
func ParseMixedLinks(links []string) ([]*node.ProxyNode, error) {
	var nodes []*node.ProxyNode
	for _, link := range links {
		link = strings.TrimSpace(link)
		if link == "" {
			continue
		}
		ns, err := dispatchLink(link)
		if err != nil {
			// log.Printf("[SKIP][input/links] %s: %v", truncate(link, 80), err)
			continue
		}
		nodes = append(nodes, ns...)
	}
	return nodes, nil
}

func dispatchLink(link string) ([]*node.ProxyNode, error) {
	switch {
	case strings.HasPrefix(link, "vmess://"):
		n, err := parseVMess(link)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil

	case strings.HasPrefix(link, "vless://"):
		n, err := parseVLESS(link)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil

	case strings.HasPrefix(link, "trojan://"):
		n, err := parseTrojan(link)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil

	case strings.HasPrefix(link, "ss://"):
		ns, err := parseSS(link)
		if err != nil {
			return nil, err
		}
		return ns, nil

	case strings.HasPrefix(link, "ssd://"):
		ns, err := parseSSD(link)
		if err != nil {
			return nil, err
		}
		return ns, nil

	case strings.HasPrefix(link, "ssr://"):
		n, err := parseSSR(link)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil

	case strings.HasPrefix(link, "hysteria2://"), strings.HasPrefix(link, "hy2://"):
		n, err := parseHysteria2(link)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil

	case strings.HasPrefix(link, "hysteria://"), strings.HasPrefix(link, "hy://"):
		n, err := parseHysteria(link)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil

	case strings.HasPrefix(link, "tuic://"):
		n, err := parseTUIC(link)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil

	case strings.HasPrefix(link, "wireguard://"), strings.HasPrefix(link, "wg://"):
		n, err := parseWireGuard(link)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil

	case strings.HasPrefix(link, "socks5://"), strings.HasPrefix(link, "socks://"):
		n, err := parseSOCKS(link)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil

	case strings.HasPrefix(link, "https://"):
		n, err := parseHTTP(link, true)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil

	case strings.HasPrefix(link, "http://"):
		n, err := parseHTTP(link, false)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil

	case strings.HasPrefix(link, "anytls://"):
		n, err := parseAnyTLS(link)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil

	case strings.HasPrefix(link, "mieru://"):
		ns, err := parseMieru(link)
		if err != nil {
			return nil, err
		}
		return ns, nil

	case strings.HasPrefix(link, "mierus://"):
		ns, err := parseMierus(link)
		if err != nil {
			return nil, err
		}
		return ns, nil

	case strings.HasPrefix(link, "sudoku://"):
		n, err := parseSudoku(link)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil

	default:
		return nil, fmt.Errorf("unrecognised link scheme")
	}
}

// ─── shared URL helpers ───────────────────────────────────────────────────────

// parseStdURL wraps url.Parse and returns the URL along with its decoded
// fragment (node name). Returns an error for truly malformed URLs.
func parseStdURL(link string) (*url.URL, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", fmt.Errorf("url.Parse: %w", err)
	}
	name := u.Fragment
	if decoded, err := url.QueryUnescape(name); err == nil {
		name = decoded
	}
	return u, name, nil
}

// queryStr returns the first value for key from query params.
func queryStr(q url.Values, key string) string {
	return q.Get(key)
}

// queryBool returns true if the key is "1" or "true" (case-insensitive).
func queryBool(q url.Values, key string) bool {
	v := strings.ToLower(q.Get(key))
	return v == "1" || v == "true"
}

// portFromStr converts a port string to int. Returns 0 on failure.
func portFromStr(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// applyTLSParams reads query params shared by VLESS / Trojan / VMess std-URL
// and populates TLS and transport-related clash map fields.
func applyTLSTransportParams(clash map[string]any, q url.Values, sniKey string) {
	security := queryStr(q, "security")
	if security == "tls" || security == "reality" {
		clash["tls"] = true
	}
	if security != "" && security != "none" {
		clash["security"] = security
	}
	if sni := queryStr(q, "sni"); sni != "" {
		clash[sniKey] = sni
	}
	if fp := queryStr(q, "fp"); fp != "" {
		clash["client-fingerprint"] = fp
	}
	if alpnRaw := queryStr(q, "alpn"); alpnRaw != "" {
		decoded, err := url.QueryUnescape(alpnRaw)
		if err != nil {
			decoded = alpnRaw
		}
		clash["alpn"] = strings.Split(decoded, ",")
	}
	if queryBool(q, "allowInsecure") || queryBool(q, "insecure") {
		clash["skip-cert-verify"] = true
	}
	if spx := queryStr(q, "spx"); spx != "" {
		clash["spider-x"] = spx
	}
	if pqv := queryStr(q, "pqv"); pqv != "" {
		clash["mldsa65-verify"] = pqv
	}
	if ech := queryStr(q, "ech"); ech != "" {
		clash["ech"] = ech
	}
	if pcs := queryStr(q, "pcs"); pcs != "" {
		clash["cert-sha"] = pcs
	}
	if fm := queryStr(q, "fm"); fm != "" {
		clash["finalmask"] = fm
	}
	if security == "reality" {
		ropts := map[string]any{}
		if pbk := queryStr(q, "pbk"); pbk != "" {
			ropts["public-key"] = pbk
		}
		if sid := queryStr(q, "sid"); sid != "" {
			ropts["short-id"] = sid
		}
		if len(ropts) > 0 {
			clash["reality-opts"] = ropts
		}
	}

	// Transport
	network := queryStr(q, "type")
	switch network {
	case "ws":
		applyWSParams(clash, q)
	case "grpc":
		clash["network"] = "grpc"
		grpcOpts := map[string]any{}
		if svc := queryStr(q, "serviceName"); svc != "" {
			grpcOpts["grpc-service-name"] = svc
		}
		if authority := queryStr(q, "authority"); authority != "" {
			grpcOpts["grpc-authority"] = authority
		}
		if mode := queryStr(q, "mode"); mode != "" {
			grpcOpts["grpc-mode"] = mode
		}
		if len(grpcOpts) > 0 {
			clash["grpc-opts"] = grpcOpts
		}
	case "httpupgrade":
		clash["network"] = "ws"
		wsOpts := map[string]any{"v2ray-http-upgrade": true}
		if path := queryStr(q, "path"); path != "" {
			wsOpts["path"] = path
		}
		if host := queryStr(q, "host"); host != "" {
			wsOpts["headers"] = map[string]any{"Host": host}
		}
		clash["ws-opts"] = wsOpts
	case "h2", "http":
		clash["network"] = "h2"
		h2Opts := map[string]any{}
		if host := queryStr(q, "host"); host != "" {
			h2Opts["host"] = []any{host}
		}
		if path := queryStr(q, "path"); path != "" {
			h2Opts["path"] = path
		}
		if len(h2Opts) > 0 {
			clash["h2-opts"] = h2Opts
		}
	case "xhttp":
		clash["network"] = "xhttp"
		xhttpOpts := map[string]any{}
		if host := queryStr(q, "host"); host != "" {
			xhttpOpts["host"] = host
		}
		if path := queryStr(q, "path"); path != "" {
			xhttpOpts["path"] = path
		}
		if mode := queryStr(q, "mode"); mode != "" {
			xhttpOpts["mode"] = mode
		} else {
			xhttpOpts["mode"] = "auto"
		}
		if extra := queryStr(q, "extra"); extra != "" {
			xhttpOpts["extra"] = extra
		}
		if len(xhttpOpts) > 0 {
			clash["xhttp-opts"] = xhttpOpts
		}
	case "tcp":
		clash["network"] = "tcp"
		if headerType := queryStr(q, "headerType"); headerType != "" && headerType != "none" {
			clash["header-type"] = headerType
		}
		if host := queryStr(q, "host"); host != "" {
			clash["host"] = host
		}
		if queryStr(q, "headerType") == "http" {
			// TCP with HTTP obfuscation — not mapped to a separate transport in clash
		}
	case "kcp":
		clash["network"] = "kcp"
		if headerType := queryStr(q, "headerType"); headerType != "" && headerType != "none" {
			clash["header-type"] = headerType
		}
		if seed := queryStr(q, "seed"); seed != "" {
			clash["seed"] = seed
		}
	case "quic":
		clash["network"] = "quic"
		if headerType := queryStr(q, "headerType"); headerType != "" && headerType != "none" {
			clash["header-type"] = headerType
		}
		if quicSecurity := queryStr(q, "quicSecurity"); quicSecurity != "" {
			clash["quic-security"] = quicSecurity
		}
		if key := queryStr(q, "key"); key != "" {
			clash["key"] = key
		}
	}
}

func applyWSParams(clash map[string]any, q url.Values) {
	clash["network"] = "ws"
	wsOpts := map[string]any{}
	if path := queryStr(q, "path"); path != "" {
		decoded, err := url.QueryUnescape(path)
		if err == nil {
			path = decoded
		}
		wsOpts["path"] = path
	}
	if host := queryStr(q, "host"); host != "" {
		wsOpts["headers"] = map[string]any{"Host": host}
	}
	if len(wsOpts) > 0 {
		clash["ws-opts"] = wsOpts
	}
}

// truncate limits a string to n bytes for log messages.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
