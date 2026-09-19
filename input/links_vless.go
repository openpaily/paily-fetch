package input

import (
	"fmt"
	"strings"

	"github.com/openpaily/paily-fetch/node"
)

// parseVLESS parses a vless:// link.
// Format: vless://uuid@host:port?type=&security=&flow=&sni=&...#name
func parseVLESS(link string) (*node.ProxyNode, error) {
	u, name, err := parseStdURL(link)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("vless URL missing uuid in userinfo")
	}
	uuid := u.User.Username()
	if uuid == "" {
		return nil, fmt.Errorf("vless URL missing uuid in userinfo")
	}
	server := u.Hostname()
	port := portFromStr(u.Port())
	if server == "" || port == 0 {
		return nil, fmt.Errorf("vless URL missing server or port")
	}

	q := u.Query()
	clash := map[string]any{
		"type":   "vless",
		"name":   name,
		"server": server,
		"port":   port,
		"uuid":   uuid,
	}

	if flow := queryStr(q, "flow"); flow != "" {
		clash["flow"] = flow
	}
	if pe := queryStr(q, "packet-encoding"); pe != "" {
		clash["packet-encoding"] = pe
	}

	if alpnRaw := queryStr(q, "alpn"); alpnRaw != "" {
		// Hysteria v1 uses comma-separated ALPN
		parts := strings.Split(alpnRaw, ",")
		result := make([]any, len(parts))
		for i, p := range parts {
			result[i] = strings.TrimSpace(p)
		}
		clash["alpn"] = result
	}

	if enc := queryStr(q, "encryption"); enc != "" {
		clash["encryption"] = enc
	}

	applyTLSTransportParams(clash, q, "servername")
	return node.New(clash)
}
