package fetcher

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openpaily/paily-fetch/input"
	"github.com/openpaily/paily-fetch/node"

	"gopkg.in/yaml.v3"
)

// ParseSubscriptionBody detects the content type of a subscription download and
// returns all proxy nodes found within it.
func ParseSubscriptionBody(raw []byte) ([]*node.ProxyNode, error) {
	kind, data := DetectKind(raw)
	switch kind {
	case KindClash:
		return parseClashYAML(data)
	case KindSingbox:
		return parseSingboxJSON(data)
	case KindURLList:
		return parseURLList(data)
	case KindNodeJSON:
		return parseNodeEnvelope(data)
	default:
		return nil, fmt.Errorf("unrecognised subscription content (first 64 bytes: %q)", truncateBytes(raw, 64))
	}
}

// ParseNodeSourceContent parses a source of type "node".
// The content is a JSON envelope: {"type":"clash|singbox|mixed","content":"…"}.
// Falls back to treating raw content as a single link string.
func ParseNodeSourceContent(content string) ([]*node.ProxyNode, error) {
	// Try the JSON envelope first.
	nodes, err := parseNodeEnvelope([]byte(content))
	if err == nil {
		return nodes, nil
	}
	// Fall back: treat as a single proxy link.
	return input.ParseMixedLinks([]string{strings.TrimSpace(content)})
}

// ─── internal parsers ─────────────────────────────────────────────────────────

func parseClashYAML(data []byte) ([]*node.ProxyNode, error) {
	// Optimisation: extract only the "proxies:" block before parsing.
	// This avoids decoding dns, rules, proxy-groups and other heavy sections.
	// On failure (nil block or unmarshal error) fall back to full-document parse.
	if block := extractProxiesBlock(data); len(block) > 0 {
		var cfg map[string]any
		if err := yaml.Unmarshal(block, &cfg); err == nil {
			return input.ParseMihomo(cfg)
		}
	}
	return parseClashYAMLFull(data)
}

// parseClashYAMLFull parses a full Clash YAML document without extraction.
// Used as the fallback path and as the baseline in benchmarks.
func parseClashYAMLFull(data []byte) ([]*node.ProxyNode, error) {
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("clash YAML parse: %w", err)
	}
	return input.ParseMihomo(cfg)
}

func parseSingboxJSON(data []byte) ([]*node.ProxyNode, error) {
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("singbox JSON parse: %w", err)
	}
	return input.ParseSingbox(cfg)
}

func parseURLList(data []byte) ([]*node.ProxyNode, error) {
	lines := strings.Split(string(data), "\n")
	return input.ParseMixedLinks(lines)
}

func parseNodeEnvelope(data []byte) ([]*node.ProxyNode, error) {
	var env struct {
		Type    string `json:"type"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("node envelope JSON: %w", err)
	}
	switch env.Type {
	case "clash":
		// content is a YAML snippet like "proxies:\n  - …"
		return parseClashYAML([]byte(env.Content))
	case "singbox":
		return parseSingboxJSON([]byte(env.Content))
	case "mixed":
		lines := strings.Split(env.Content, "\n")
		return input.ParseMixedLinks(lines)
	default:
		return nil, fmt.Errorf("unknown node envelope type %q", env.Type)
	}
}

func truncateBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
