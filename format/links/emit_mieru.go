package links

import (
	"fmt"
	"net/url"
	"strings"
)

// emitMieru generates a mierus:// link for a mieru proxy node.
// Format: mierus://username:password@host?profile=<name>&port=<n>&protocol=<TCP|UDP>[&multiplexing=...]
//
// Notes:
// - One mierus:// URL describes a single server.
// - If the clash map has "port-range" it is used as the port value; otherwise "port" is used.
// - The profile name is taken from the clash "name" field (which is the profileName set during parsing).
func emitMieru(clash map[string]any, name string) (string, bool) {
	server := lStr(clash, "server")
	username := lStr(clash, "username")
	password := lStr(clash, "password")
	if server == "" || username == "" || password == "" {
		return "", false
	}

	q := url.Values{}

	// Profile name: the clash "name" field carries the profile name during parsing.
	// Use the resolved output name as profile.
	q.Set("profile", name)

	// Port or port-range
	portRange := lStr(clash, "port-range")
	if portRange != "" {
		q.Set("port", portRange)
	} else if port := lInt(clash, "port"); port > 0 {
		q.Set("port", fmt.Sprintf("%d", port))
	}

	// Protocol (transport)
	transport := lStr(clash, "transport")
	if transport == "" {
		transport = "TCP"
	}
	q.Set("protocol", strings.ToUpper(transport))

	// Optional params
	if mux := lStr(clash, "multiplexing"); mux != "" {
		q.Set("multiplexing", mux)
	}
	if hm := lStr(clash, "handshake-mode"); hm != "" {
		q.Set("handshake-mode", hm)
	}
	if tp := lStr(clash, "traffic-pattern"); tp != "" {
		q.Set("traffic-pattern", tp)
	}

	// IPv6 hosts must be enclosed in brackets (url.URL handles this automatically,
	// but we build the URL manually to avoid double-encoding).
	host := server
	if strings.ContainsRune(host, ':') {
		host = "[" + host + "]"
	}

	link := fmt.Sprintf("mierus://%s:%s@%s?%s",
		url.QueryEscape(username),
		url.QueryEscape(password),
		host,
		q.Encode(),
	)
	return link, true
}
