package input

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/openpaily/paily-fetch/node"
)

// parseTUIC parses a tuic:// link.
// Format (V5): tuic://uuid:password@host:port?sni=&alpn=&insecure=&congestion_control=#name
// Note: TUIC V4 (token only, no uuid) has no link format — it cannot appear here.
func parseTUIC(link string) (*node.ProxyNode, error) {
	u, name, err := parseStdURL(link)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("tuic URL missing userinfo")
	}
	server := u.Hostname()
	port := portFromStr(u.Port())
	if server == "" || port == 0 {
		return nil, fmt.Errorf("tuic URL missing server or port")
	}

	// userinfo = uuid:password (split on first ':')
	userStr := u.User.String()
	// url.User encodes the password with password accessor; use raw string split
	colonIdx := strings.IndexByte(userStr, ':')
	uuid := userStr
	password := ""
	if colonIdx >= 0 {
		uuid = userStr[:colonIdx]
		password = userStr[colonIdx+1:]
	}
	if password == "" {
		// url.URL parses uuid as Username and password as Password
		uuid = u.User.Username()
		password, _ = u.User.Password()
	}
	if uuid == "" {
		return nil, fmt.Errorf("tuic URL missing uuid in userinfo")
	}

	q := u.Query()
	clash := map[string]any{
		"type":     "tuic",
		"name":     name,
		"server":   server,
		"port":     port,
		"uuid":     uuid,
		"password": password,
	}

	if sni := queryStr(q, "sni"); sni != "" {
		clash["sni"] = sni
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
	if queryBool(q, "insecure") || queryBool(q, "allowInsecure") {
		clash["skip-cert-verify"] = true
	}
	if cc := queryStr(q, "congestion_control"); cc != "" {
		clash["congestion-controller"] = cc
	}
	if udpMode := queryStr(q, "udp_relay_mode"); udpMode != "" {
		clash["udp-relay-mode"] = udpMode
	}

	return node.New(clash)
}
