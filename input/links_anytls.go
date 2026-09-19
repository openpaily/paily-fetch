package input

import (
	"fmt"

	"github.com/openpaily/paily-fetch/node"
)

// parseAnyTLS parses an anytls:// link.
// Format: anytls://password@host[:port]/?sni=&insecure=&remarks=#name
// The port defaults to 443 if omitted.
func parseAnyTLS(link string) (*node.ProxyNode, error) {
	u, name, err := parseStdURL(link)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("anytls URL missing password in userinfo")
	}

	password := u.User.Username()
	if password == "" {
		return nil, fmt.Errorf("anytls URL missing password in userinfo")
	}
	server := u.Hostname()
	portStr := u.Port()
	port := portFromStr(portStr)
	if port == 0 {
		port = 443
	}
	if server == "" {
		return nil, fmt.Errorf("anytls URL missing server")
	}

	q := u.Query()
	if name == "" {
		name = queryStr(q, "remarks")
	}
	if name == "" {
		name = server
	}

	clash := map[string]any{
		"type":     "anytls",
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

	return node.New(clash)
}
