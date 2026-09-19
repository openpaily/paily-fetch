//go:build !noclash

package node

import (
	"errors"
	"fmt"
	"maps"

	"github.com/metacubex/mihomo/adapter"
)

// ProxyNode holds a single proxy's configuration as a clash-compatible map.
// The raw map must have at minimum "name" (string) and "type" (string) fields.
type ProxyNode struct {
	name  string
	ptype string
	raw   map[string]any
}

// New creates a ProxyNode from a clash proxy entry map.
// Returns an error if "name" or "type" fields are missing or not strings.
// A defensive copy of raw is made.
func New(raw map[string]any) (*ProxyNode, error) {
	name, ok := raw["name"].(string)
	if !ok || name == "" {
		raw["name"] = "node"
	}
	ptype, ok := raw["type"].(string)
	if !ok || ptype == "" {
		return nil, errors.New("proxy map missing or empty \"type\" field")
	}

	copied := maps.Clone(raw)

	return &ProxyNode{
		name:  name,
		ptype: ptype,
		raw:   copied,
	}, nil
}

// Name returns the proxy node's name.
func (n *ProxyNode) Name() string {
	return n.name
}

// Type returns the proxy node's protocol type (e.g. "vmess", "vless", "ss").
func (n *ProxyNode) Type() string {
	return n.ptype
}

// ClashMap returns the underlying clash proxy entry map.
// Callers must not modify the returned map.
func (n *ProxyNode) ClashMap() map[string]any {
	return n.raw
}

// Validate checks whether the node's clash map can be parsed by mihomo.
// Returns an error if mihomo rejects the configuration.
func (n *ProxyNode) Validate() error {
	_, err := adapter.ParseProxy(n.raw)
	if err != nil {
		return fmt.Errorf("validate %q (%s): %w", n.name, n.ptype, err)
	}
	return nil
}
