package input

import (
	"fmt"

	"github.com/openpaily/paily-fetch/node"
)

// ParseMihomo parses a mihomo/clash configuration map and returns ProxyNodes for all
// entries in the "proxies" list. cfg is the entire decoded config map (e.g. from YAML).
// Individual parse failures are logged with [SKIP][input/mihomo] and skipped.
// A non-nil error is returned only when the "proxies" field itself is malformed.
func ParseMihomo(cfg map[string]any) ([]*node.ProxyNode, error) {
	raw, ok := cfg["proxies"]
	if !ok {
		return nil, nil
	}

	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("proxies field is not a list")
	}

	nodes := make([]*node.ProxyNode, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			// log.Printf("[SKIP][input/mihomo] #%d: entry is not a map", i)
			continue
		}

		if _, ok := m["name"]; !ok {
			m["name"] = "node"
		}

		n, err := node.New(m)
		if err != nil {
			name, _ := m["name"].(string)
			if name == "" {
				name = fmt.Sprintf("#%d", i)
			}
			// log.Printf("[SKIP][input/mihomo] %s: %v", name, err)
			continue
		}

		nodes = append(nodes, n)
	}

	return nodes, nil
}
