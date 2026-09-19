package input

import (
	"fmt"
	"strings"

	"github.com/openpaily/paily-fetch/node"
)

// parseWireGuard parses a wireguard:// or wg:// link.
// Format: wireguard://privatekey@host:port?publickey=&reserved=&address=&mtu=#name
func parseWireGuard(link string) (*node.ProxyNode, error) {
	normalized := link
	if strings.HasPrefix(link, "wg://") {
		normalized = "wireguard://" + link[len("wg://"):]
	}

	u, name, err := parseStdURL(normalized)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("wireguard URL missing private key in userinfo")
	}

	privateKey := u.User.Username()
	server := u.Hostname()
	port := portFromStr(u.Port())
	if server == "" || port == 0 {
		return nil, fmt.Errorf("wireguard URL missing server or port")
	}

	q := u.Query()
	publicKey := queryStr(q, "publickey")
	if publicKey == "" {
		return nil, fmt.Errorf("wireguard URL missing 'publickey' param")
	}

	clash := map[string]any{
		"type":        "wireguard",
		"name":        name,
		"server":      server,
		"port":        port,
		"private-key": privateKey,
		"public-key":  publicKey,
	}

	if address := queryStr(q, "address"); address != "" {
		// Treat as IPv4 or IPv6 based on colon presence
		if strings.Contains(address, ":") {
			clash["ipv6"] = address
		} else {
			clash["ip"] = address
		}
	}

	if mtu := portFromStr(queryStr(q, "mtu")); mtu > 0 {
		clash["mtu"] = mtu
	}

	if reserved := queryStr(q, "reserved"); reserved != "" {
		clash["reserved"] = parseReserved(reserved)
	}
	if allowedIPs := queryStr(q, "allowedips"); allowedIPs != "" {
		clash["allowed-ips"] = strings.Split(allowedIPs, ",")
	} else {
		clash["allowed-ips"] = []string{"0.0.0.0/0"}
	}

	return node.New(clash)
}

// parseReserved converts a WireGuard reserved string to []uint8-compatible []int.
// Accepts comma-separated ints "0,0,0"; returns the raw string if not parseable.
func parseReserved(s string) any {
	parts := strings.Split(s, ",")
	if len(parts) == 3 {
		result := make([]any, 3)
		for i, p := range parts {
			n := portFromStr(strings.TrimSpace(p))
			result[i] = n
		}
		return result
	}
	return s // base64 string or other format – pass through
}
