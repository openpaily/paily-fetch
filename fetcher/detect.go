// Package fetcher implements the periodic subscription fetcher service.
// It downloads proxy subscriptions, parses them, and reports nodes to paily-core.
package fetcher

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// ContentKind classifies raw subscription content.
type ContentKind int

const (
	KindUnknown  ContentKind = iota
	KindClash                // Mihomo/Clash YAML with top-level "proxies" key
	KindSingbox              // Sing-box JSON with top-level "outbounds" key
	KindURLList              // Newline-separated protocol links (vmess://, ss://, …)
	KindNodeJSON             // Paily node envelope: {"type":"clash|singbox|mixed","content":"…"}
)

// knownSchemes is the set of proxy URI prefixes used to recognise a URL-list.
var knownSchemes = []string{
	"vmess://", "vless://", "trojan://",
	"ss://", "ssr://",
	"hysteria://", "hy2://", "hysteria2://",
	"tuic://", "wg://", "wireguard://",
	"socks5://", "socks://",
	"http://", "https://",
	"anytls://",
	"mierus://", "mieru://",
	"sudoku://",
}

// DetectKind inspects raw bytes and returns the best-matching ContentKind.
// The detection order (inspired by subconverter) is:
//  1. Paily node JSON envelope
//  2. Sing-box JSON (contains "outbounds" array)
//  3. Clash YAML (contains top-level "proxies" key)
//  4. Decode base64 → re-apply steps 1-3
//  5. URL list (one or more lines begin with a known scheme)
//  6. Base64 URL list (base64 of step 5)
func DetectKind(raw []byte) (ContentKind, []byte) {
	trimmed := bytes.TrimSpace(raw)

	if k, b := detectDirect(trimmed); k != KindUnknown {
		return k, b
	}

	// Try base64 decode
	if decoded, err := base64DecodeBytes(trimmed); err == nil {
		if k, b := detectDirect(decoded); k != KindUnknown {
			return k, b
		}
	}

	return KindUnknown, raw
}

// detectDirect runs detection on raw bytes without any base64 unwrapping.
func detectDirect(data []byte) (ContentKind, []byte) {
	s := strings.TrimSpace(string(data))

	// 1. Paily node JSON envelope
	if looksLikeJSON(s) {
		var env nodeEnvelope
		if json.Unmarshal([]byte(s), &env) == nil && env.Type != "" && env.Content != "" {
			return KindNodeJSON, []byte(s)
		}
		// 2. Sing-box JSON
		var obj map[string]json.RawMessage
		if json.Unmarshal([]byte(s), &obj) == nil {
			if _, ok := obj["outbounds"]; ok {
				return KindSingbox, []byte(s)
			}
		}
	}

	// 3. Clash YAML
	if containsProxiesKey([]byte(s)) {
		return KindClash, []byte(s)
	}

	// 4. URL list — check first non-empty line
	if hasURLListLines(s) {
		return KindURLList, []byte(s)
	}

	return KindUnknown, nil
}

// nodeEnvelope is the paily-specific node content envelope.
type nodeEnvelope struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}

// looksLikeJSON returns true when the trimmed string starts with '{' or '['.
func looksLikeJSON(s string) bool {
	return len(s) > 0 && (s[0] == '{' || s[0] == '[')
}

// clashHintKeys are top-level YAML keys that appear in virtually all
// Clash/Mihomo configurations. They are used as secondary detection signals
// when "proxies:" is absent (e.g. proxy-providers-only configs) or has not
// yet been seen in the probe window.
var clashHintKeys = [][]byte{
	[]byte("mixed-port:"),
	[]byte("allow-lan:"),
	[]byte("dns:"),
	[]byte("proxy-groups:"),
	[]byte("rules:"),
}

// containsProxiesKey returns true when data looks like a Clash/Mihomo config.
// The logic has three phases:
//
//  1. Scan the first 4 KB for an early top-level "proxies:" key (fast path) or
//     for known Clash hint keys that confirm the document type.
//
//  2. If hint keys were found but "proxies:" was not in the first 4 KB, scan
//     the full document for a top-level "proxies:" key (handles long subscription
//     files where the proxies block appears far into the document).
//
//  3. If hint keys confirm this is a Clash document but no top-level "proxies:"
//     key exists anywhere (e.g. proxy-providers-only configurations), still
//     report true so the caller can attempt a full-document parse.
//
// "proxies:" is matched in unquoted, double-quoted, and single-quoted forms.
func containsProxiesKey(data []byte) bool {
	// Phase 1: scan the first 4 KB.
	probe := data
	if len(probe) > 4096 {
		probe = probe[:4096]
	}
	foundHint := false
	for _, line := range bytes.Split(probe, []byte("\n")) {
		bare := trimCR(line)
		if isTopLevelProxiesKey(bare) {
			return true // proxies: found early — done
		}
		if !foundHint {
			for _, key := range clashHintKeys {
				if isTopLevelKey(bare, key) {
					foundHint = true
					break
				}
			}
		}
	}
	if !foundHint {
		// No Clash signals in first 4 KB: not a Clash document.
		return false
	}
	// Phase 2: hint keys confirmed Clash; scan the full document for a
	// top-level proxies: key (it may appear after the 4 KB probe window).
	for _, line := range bytes.Split(data, []byte("\n")) {
		if isTopLevelProxiesKey(trimCR(line)) {
			return true
		}
	}
	// Phase 3: confirmed Clash (hint keys present) but no top-level proxies:
	// key found — proxy-providers-only config. Still report as Clash.
	return true
}

// hasURLListLines returns true when at least one of the first 128 non-empty
// lines starts with a known proxy URI scheme.
// All 128 lines (or the entire content if shorter) are scanned before giving up,
// so files with a preamble comment or a few blank lines are still recognised.
func hasURLListLines(s string) bool {
	checked := 0
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, scheme := range knownSchemes {
			if strings.HasPrefix(line, scheme) {
				return true
			}
		}
		checked++
		if checked >= 128 {
			break
		}
	}
	return false
}

// base64DecodeBytes tries standard then URL base64 (with padding normalisation).
func base64DecodeBytes(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	// Remove newlines that some clients insert for line-length compliance.
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	// Normalise padding.
	s = strings.TrimRight(s, "=")
	pad := (4 - len(s)%4) % 4
	s += strings.Repeat("=", pad)

	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
