package clash

import (
	"fmt"
	"maps"

	"github.com/openpaily/paily-fetch/internal/format"
	"github.com/openpaily/paily-fetch/node"
	"gopkg.in/yaml.v3"
)

// Generator implements format.FormatGenerator for the clash output format.
// It collects proxy entries as clash map[string]any items and serialises them
// as a YAML document with a top-level "proxies:" list.
//
// All clash-supported proxy types are accepted; no skip conditions apply.
type Generator struct {
	items []map[string]any
}

var _ format.FormatGenerator = (*Generator)(nil)

// Push appends a proxy entry to the internal list.
// If name is non-empty it overrides the "name" field in the output entry;
// otherwise the original n.Name() value is kept.
// FormatConfig is not used by the clash format and may be nil.
func (g *Generator) Push(n *node.ProxyNode, name string) {
	entry := maps.Clone(n.ClashMap())
	if name != "" {
		entry["name"] = name
	}
	g.items = append(g.items, entry)
}

// Generate serialises all pushed entries as YAML.
//
// When config contains a non-empty Template string, the template is parsed as
// a full Clash YAML config and the generator:
//   - replaces the top-level "proxies" list with all pushed nodes, and
//   - appends every pushed node's name to the "proxies" list of every proxy-group.
//
// When config is nil or Template is empty, a plain document is emitted:
//
//	proxies:
//	  - {name: ..., type: ..., ...}
func (g *Generator) Generate(cfg format.FormatConfig) ([]byte, error) {
	c := parseConfig(cfg)
	if c.Template == "" {
		out := map[string][]map[string]any{"proxies": g.items}
		data, err := yaml.Marshal(out)
		if err != nil {
			return nil, fmt.Errorf("clash generator: yaml.Marshal: %w", err)
		}
		return data, nil
	}

	// Template mode: parse the full Clash config and inject nodes.
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(c.Template), &doc); err != nil {
		return nil, fmt.Errorf("clash generator: parse template YAML: %w", err)
	}

	// Replace the proxies list.
	doc["proxies"] = g.items

	// Append every pushed node's name to each proxy-group's proxies list.
	names := g.proxyNames()
	if groups, ok := doc["proxy-groups"].([]any); ok {
		for _, grp := range groups {
			gm, ok := grp.(map[string]any)
			if !ok {
				continue
			}
			existing, _ := gm["proxies"].([]any)
			for _, n := range names {
				existing = append(existing, n)
			}
			gm["proxies"] = existing
		}
	}

	data, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("clash generator: yaml.Marshal template: %w", err)
	}
	return data, nil
}

// proxyNames returns the "name" field of every pushed proxy item, in order.
func (g *Generator) proxyNames() []string {
	names := make([]string, 0, len(g.items))
	for _, item := range g.items {
		if n, ok := item["name"].(string); ok && n != "" {
			names = append(names, n)
		}
	}
	return names
}
