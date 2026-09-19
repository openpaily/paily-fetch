package input

import (
	"net/url"

	"github.com/openpaily/paily-fetch/node"
)

// parseHTTP parses http:// and https:// links.
// Format: http://[user:pass@]host:port[?remarks=name]
// TLS is determined by the tls parameter.
func parseHTTP(link string, tls bool) (*node.ProxyNode, error) {
	u, name, err := parseStdURL(link)
	if err != nil {
		return nil, err
	}

	server := u.Hostname()
	port := portFromStr(u.Port())
	if server == "" {
		return &node.ProxyNode{}, nil
	}
	if port == 0 {
		if tls {
			port = 443
		} else {
			port = 80
		}
	}

	// Name from fragment or remarks param
	if name == "" {
		q := u.Query()
		name = queryStr(q, "remarks")
	}
	if name == "" {
		name = server
	}

	clash := map[string]any{
		"type":   "http",
		"name":   name,
		"server": server,
		"port":   port,
	}
	if tls {
		clash["tls"] = true
	}
	if u.User != nil {
		if user := u.User.Username(); user != "" {
			clash["username"] = user
		}
		if pass, ok := u.User.Password(); ok && pass != "" {
			clash["password"] = pass
		}
	}

	// Support ?security=tls override
	q := u.Query()
	if queryStr(q, "security") == "tls" {
		clash["tls"] = true
	}

	return node.New(clash)
}

// unescapeURL is a package-level alias for net/url.QueryUnescape,
// used by other files in the input package.
func unescapeURL(s string) (string, error) {
	return url.QueryUnescape(s)
}
