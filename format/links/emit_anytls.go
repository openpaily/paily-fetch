package links

import (
	"fmt"
	"net/url"
)

// emitAnyTLS generates an anytls:// link.
// Format: anytls://password@host:port/?sni=&insecure=#name
func emitAnyTLS(clash map[string]any, name string) (string, bool) {
	server := lStr(clash, "server")
	port := lInt(clash, "port")
	password := lStr(clash, "password")
	if server == "" || password == "" {
		return "", false
	}
	if port == 0 {
		port = 443
	}

	q := url.Values{}
	if sni := lStr(clash, "sni"); sni != "" {
		q.Set("sni", sni)
	}
	if lBool(clash, "skip-cert-verify") {
		q.Set("insecure", "1")
	}

	link := fmt.Sprintf("anytls://%s@%s/?%s#%s",
		url.QueryEscape(password),
		hostPort(server, port),
		q.Encode(),
		fragment(name),
	)
	return link, true
}
