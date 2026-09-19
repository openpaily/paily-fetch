package input

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/openpaily/paily-fetch/node"
)

// parseHysteria parses hysteria:// or hy:// links.
// Format: hysteria://host:port?auth_str=&upmbps=&downmbps=&peer=&insecure=&obfsParam=&alpn=&protocol=#name
func parseHysteria(link string) (*node.ProxyNode, error) {
	// Normalise scheme so url.Parse works
	normalized := link
	if strings.HasPrefix(link, "hy://") {
		normalized = "hysteria://" + link[len("hy://"):]
	}

	u, name, err := parseStdURL(normalized)
	if err != nil {
		return nil, err
	}

	server := u.Hostname()
	port := portFromStr(u.Port())
	if server == "" || port == 0 {
		return nil, fmt.Errorf("hysteria URL missing server or port")
	}

	q := u.Query()

	clash := map[string]any{
		"type":   "hysteria",
		"name":   name,
		"server": server,
		"port":   port,
	}

	// Authentication: auth_str preferred; fall back to auth (base64)
	if authStr := queryStr(q, "auth_str"); authStr != "" {
		clash["auth-str"] = authStr
	} else if auth := queryStr(q, "auth"); auth != "" {
		clash["auth-str"] = auth
	}

	if upmbps := queryStr(q, "upmbps"); upmbps != "" {
		clash["up"] = upmbps + " Mbps"
	}
	if downmbps := queryStr(q, "downmbps"); downmbps != "" {
		clash["down"] = downmbps + " Mbps"
	}

	// SNI: peer param used by Hysteria v1
	if peer := queryStr(q, "peer"); peer != "" {
		clash["sni"] = peer
	}

	if queryBool(q, "insecure") {
		clash["skip-cert-verify"] = true
	}

	if obfs := queryStr(q, "obfsParam"); obfs != "" {
		clash["obfs"] = obfs
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

	if protocol := queryStr(q, "protocol"); protocol != "" && protocol != "udp" {
		clash["protocol"] = protocol
	}

	if sni := queryStr(q, "sni"); sni != "" {
		clash["sni"] = sni
	}

	// Port hopping  (subconverter-style parameter)
	if ports := queryStr(q, "ports"); ports != "" {
		clash["ports"] = ports
	}

	return node.New(clash)
}

// parseHysteria2 parses hysteria2:// or hy2:// links.
// Format: hysteria2://password@host:port?sni=&insecure=&obfs=&obfs-password=&...#name
func parseHysteria2(link string) (*node.ProxyNode, error) {
	normalized := link
	if strings.HasPrefix(link, "hy2://") {
		normalized = "hysteria2://" + link[len("hy2://"):]
	}

	u, name, err := parseStdURL(normalized)
	if err != nil {
		return nil, err
	}

	server := u.Hostname()
	port := portFromStr(u.Port())
	if server == "" || port == 0 {
		return nil, fmt.Errorf("hysteria2 URL missing server or port")
	}

	// Allow password-less auth (no userinfo) for format that puts pass in query
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}

	q := u.Query()
	// Some clients put password in query
	if password == "" {
		password = queryStr(q, "password")
	}

	clash := map[string]any{
		"type":     "hysteria2",
		"name":     name,
		"server":   server,
		"port":     port,
		"password": password,
	}

	if sni := queryStr(q, "sni"); sni != "" {
		clash["sni"] = sni
	}
	if queryBool(q, "insecure") || queryBool(q, "allowInsecure") {
		clash["skip-cert-verify"] = true
	}
	if obfs := queryStr(q, "obfs"); obfs != "" {
		clash["obfs"] = obfs
	}
	if obfsPass := queryStr(q, "obfs-password"); obfsPass != "" {
		clash["obfs-password"] = obfsPass
	}
	if up := queryStr(q, "up"); up != "" {
		clash["up"] = up
	}
	if down := queryStr(q, "down"); down != "" {
		clash["down"] = down
	}

	// Port hopping
	if ports := queryStr(q, "ports"); ports != "" {
		clash["ports"] = ports
	} else if mport := queryStr(q, "mport"); mport != "" {
		// v2rayN uses mport
		clash["ports"] = mport
	}

	if alpnRaw := queryStr(q, "alpn"); alpnRaw != "" {
		decoded, err := url.QueryUnescape(alpnRaw)
		if err == nil {
			alpnRaw = decoded
		}
		parts := strings.Split(alpnRaw, ",")
		result := make([]any, len(parts))
		for i, p := range parts {
			result[i] = strings.TrimSpace(p)
		}
		clash["alpn"] = result
	}

	if pinSHA256 := queryStr(q, "pinSHA256"); pinSHA256 != "" {
		clash["fingerprint"] = pinSHA256
	}

	return node.New(clash)
}
