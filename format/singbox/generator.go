package singbox

import (
	"encoding/json"
	"fmt"

	//"fmt"

	"github.com/openpaily/paily-fetch/internal/format"
	"github.com/openpaily/paily-fetch/node"
)

// Generator implements format.FormatGenerator for the sing-box output format.
// Each Push converts a ClashMap to a sing-box outbound map[string]any and
// appends it to items. Generate serialises all items as JSON {"outbounds": [...]}.
type Generator struct {
	items []map[string]any
}

var _ format.FormatGenerator = (*Generator)(nil)

// skipTypes are protocol types unsupported by sing-box, rejected unconditionally.
var skipTypes = map[string]bool{
	"ssr":         true,
	"wireguard":   true,
	"masque":      true,
	"mieru":       true,
	"sudoku":      true,
	"snell":       true,
	"ssh":         true,
	"trusttunnel": true,
}

// nonStandardSSPlugins are SS plugins unsupported by sing-box.
var nonStandardSSPlugins = map[string]bool{
	"shadow-tls":  true,
	"restls":      true,
	"gost-plugin": true,
	"kcptun":      true,
}

// Push converts n's ClashMap to a sing-box outbound and appends it to internal state.
// Unsupported protocols or configurations are skipped with a log message.
// The name parameter overrides the tag in the output; empty string keeps n.Name().
func (g *Generator) Push(n *node.ProxyNode, name string) {
	resolvedName := name
	if resolvedName == "" {
		resolvedName = n.Name()
	}
	ptype := n.Type()
	clash := n.ClashMap()

	// Unconditional type skip
	if skipTypes[ptype] {
		// log.Printf("[SKIP][format/singbox] %q (%s): protocol not supported by sing-box", resolvedName, ptype)
		return
	}

	// Hysteria V1 special modes
	if ptype == "hysteria" {
		if clashStr(clash, "obfs") == "wechat-video" {
			// log.Printf("[SKIP][format/singbox] %q (%s): obfs=wechat-video not supported by sing-box", resolvedName, ptype)
			return
		}
		if clashStr(clash, "protocol") == "faketcp" {
			// log.Printf("[SKIP][format/singbox] %q (%s): protocol=faketcp not supported by sing-box", resolvedName, ptype)
			return
		}
	}

	// SS non-standard plugins
	if ptype == "ss" {
		if nonStandardSSPlugins[clashStr(clash, "plugin")] {
			// log.Printf("[SKIP][format/singbox] %q (%s): plugin %q not supported by sing-box",
			// 	resolvedName, ptype, clashStr(clash, "plugin"))
			return
		}
	}

	// Trojan with shadowsocks layer (ss-opts)
	if ptype == "trojan" {
		if v := clash["ss-opts"]; v != nil {
			// log.Printf("[SKIP][format/singbox] %q (%s): ss-opts not supported by sing-box", resolvedName, ptype)
			return
		}
	}

	// TUIC V4 (token-only, no uuid)
	if ptype == "tuic" {
		_, hasToken := clash["token"]
		_, hasUUID := clash["uuid"]
		if hasToken && !hasUUID {
			// log.Printf("[SKIP][format/singbox] %q (%s): TUIC V4 (token-only) not supported", resolvedName, ptype)
			return
		}
	}

	// Convert
	var ob map[string]any
	switch ptype {
	case "vmess":
		ob = toSingboxVMess(clash, resolvedName)
	case "vless":
		ob = toSingboxVLESS(clash, resolvedName)
	case "trojan":
		ob = toSingboxTrojan(clash, resolvedName)
	case "ss":
		ob = toSingboxSS(clash, resolvedName)
	case "hysteria":
		ob = toSingboxHysteria(clash, resolvedName)
	case "hysteria2":
		ob = toSingboxHysteria2(clash, resolvedName)
	case "tuic":
		ob = toSingboxTUIC(clash, resolvedName)
	case "socks5":
		ob = toSingboxSOCKS(clash, resolvedName)
	case "http":
		ob = toSingboxHTTP(clash, resolvedName)
	case "anytls":
		ob = toSingboxAnyTLS(clash, resolvedName)
	default:
		// log.Printf("[SKIP][format/singbox] %q (%s): unsupported protocol", resolvedName, ptype)
		return
	}

	if ob != nil {
		g.items = append(g.items, ob)
	}
}

// Generate serialises all pushed outbounds as JSON.
//
// When config contains a non-empty Template string, the template is parsed as a
// full sing-box JSON configuration and the generator:
//   - keeps management outbounds from the template (see managementTypes in config.go),
//   - appends every pushed node tag to the "outbounds" list of every selector/urltest,
//   - assembles: [selector/urltest] + [pushed proxy outbounds] + [direct/other infra].
//
// When config is nil or Template is empty, a plain {"outbounds": [...]} document is emitted.
func (g *Generator) Generate(cfg format.FormatConfig) ([]byte, error) {
	c := parseConfig(cfg)
	if c.Template == "" {
		out := map[string]any{"outbounds": g.items}
		data, err := json.Marshal(out)
		if err != nil {
			return nil, fmt.Errorf("singbox generator: json.Marshal: %w", err)
		}
		return data, nil
	}

	// Template mode: parse and inject.
	var doc map[string]any
	if err := json.Unmarshal([]byte(c.Template), &doc); err != nil {
		return nil, fmt.Errorf("singbox generator: parse template JSON: %w", err)
	}

	// Collect tags of all pushed proxy outbounds.
	nodeTags := make([]string, 0, len(g.items))
	for _, item := range g.items {
		if tag, ok := item["tag"].(string); ok && tag != "" {
			nodeTags = append(nodeTags, tag)
		}
	}

	// Separate template outbounds: routing outbounds are kept; proxy outbounds are discarded.
	var preProxy []any  // selector, urltest (reference proxies — come first)
	var postProxy []any // direct, dns, block, tun, etc. (come last)

	if rawObs, ok := doc["outbounds"].([]any); ok {
		for _, raw := range rawObs {
			ob, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			obType, _ := ob["type"].(string)
			if !managementTypes[obType] {
				continue // discard old proxy outbounds
			}
			if obType == "selector" || obType == "urltest" {
				// Append pushed node tags to this outbound's list.
				existing, _ := ob["outbounds"].([]any)
				for _, t := range nodeTags {
					existing = append(existing, t)
				}
				ob["outbounds"] = existing
				preProxy = append(preProxy, ob)
			} else {
				postProxy = append(postProxy, ob)
			}
		}
	}

	// Build final outbounds: [selector/urltest] + [proxy items] + [direct/infra].
	finalObs := make([]any, 0, len(preProxy)+len(g.items)+len(postProxy))
	for _, ob := range preProxy {
		finalObs = append(finalObs, ob)
	}
	for _, item := range g.items {
		finalObs = append(finalObs, item)
	}
	for _, ob := range postProxy {
		finalObs = append(finalObs, ob)
	}

	doc["outbounds"] = finalObs

	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("singbox generator: json.Marshal template: %w", err)
	}
	return data, nil
}
