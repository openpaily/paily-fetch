package links

import (
	"encoding/json"
	"strings"

	"github.com/openpaily/paily-fetch/internal/format"
	"github.com/openpaily/paily-fetch/node"
)

// preference constants
const (
	prefV2rayN       = "v2rayn"
	prefSubconverter = "subconverter"
)

// skipTypes are types that have no standard link format.
var skipTypes = map[string]bool{
	"masque":      true,
	"snell":       true,
	"ssh":         true,
	"trusttunnel": true,
}

// linksEntry holds the clash map and output name for deferred link generation.
type linksEntry struct {
	raw  map[string]any
	name string
}

// Generator implements format.FormatGenerator for the links output format.
// Links are generated lazily in Generate() so that FormatConfig preference
// changes are free (no re-Push needed).
type Generator struct {
	entries []linksEntry
}

var _ format.FormatGenerator = (*Generator)(nil)

// Push defers link generation; only stores the clash map + resolved name.
// Unsupported protocols are logged and skipped.
func (g *Generator) Push(n *node.ProxyNode, name string) {
	resolvedName := name
	if resolvedName == "" {
		resolvedName = n.Name()
	}
	if skipTypes[n.Type()] {
		// log.Printf("[SKIP][format/links] %q (%s): no standard link format", resolvedName, n.Type())
		return
	}
	g.entries = append(g.entries, linksEntry{raw: n.ClashMap(), name: resolvedName})
}

// Generate encodes all pushed entries to link strings according to the FormatConfig.
// The output is one link per line.
func (g *Generator) Generate(cfg format.FormatConfig) ([]byte, error) {
	pref := prefV2rayN
	if len(cfg) > 0 {
		var conf struct {
			Default string `json:"default"`
		}
		if err := json.Unmarshal(cfg, &conf); err == nil && conf.Default != "" {
			pref = conf.Default
		}
	}

	out := make([]string, 0, len(g.entries))
	for _, e := range g.entries {
		link, ok := emitLink(e.raw, e.name, pref)
		if !ok {
			// ptype, _ := e.raw["type"].(string)
			// log.Printf("[SKIP][format/links] %q (%s): no standard link format", e.name, ptype)
			continue
		}
		out = append(out, link)
	}
	return []byte(strings.Join(out, "\n")), nil
}

// emitLink dispatches to the per-protocol emit function.
// Returns (link, true) on success or ("", false) when the protocol has no link format.
func emitLink(clash map[string]any, name, pref string) (string, bool) {
	ptype, _ := clash["type"].(string)
	switch ptype {
	case "vmess":
		return emitVMess(clash, name, pref)
	case "vless":
		return emitVLESS(clash, name)
	case "trojan":
		return emitTrojan(clash, name)
	case "ss":
		return emitSS(clash, name)
	case "ssr":
		return emitSSR(clash, name)
	case "hysteria":
		return emitHysteria(clash, name)
	case "hysteria2":
		return emitHysteria2(clash, name, pref)
	case "tuic":
		return emitTUIC(clash, name)
	case "wireguard":
		return emitWireGuard(clash, name)
	case "socks5":
		return emitSOCKS(clash, name)
	case "http":
		return emitHTTP(clash, name)
	case "anytls":
		return emitAnyTLS(clash, name)
	case "mieru":
		return emitMieru(clash, name)
	case "sudoku":
		return emitSudoku(clash, name)
	default:
		return "", false
	}
}
