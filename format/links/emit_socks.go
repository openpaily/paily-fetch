package links

import (
	"fmt"
	"net/url"
)

// emitSOCKS generates a socks5:// link.
func emitSOCKS(clash map[string]any, name string) (string, bool) {
	server := lStr(clash, "server")
	port := lInt(clash, "port")
	if server == "" || port == 0 {
		return "", false
	}

	userpart := ""
	if user := lStr(clash, "username"); user != "" {
		pass := lStr(clash, "password")
		if pass != "" {
			userpart = url.QueryEscape(user) + ":" + url.QueryEscape(pass) + "@"
		} else {
			userpart = url.QueryEscape(user) + "@"
		}
	}

	link := fmt.Sprintf("socks5://%s%s#%s",
		userpart,
		hostPort(server, port),
		fragment(name),
	)
	return link, true
}

// emitHTTP generates an http:// or https:// link.
func emitHTTP(clash map[string]any, name string) (string, bool) {
	server := lStr(clash, "server")
	port := lInt(clash, "port")
	if server == "" || port == 0 {
		return "", false
	}

	scheme := "http"
	if lBool(clash, "tls") {
		scheme = "https"
	}

	userpart := ""
	if user := lStr(clash, "username"); user != "" {
		pass := lStr(clash, "password")
		if pass != "" {
			userpart = url.QueryEscape(user) + ":" + url.QueryEscape(pass) + "@"
		} else {
			userpart = url.QueryEscape(user) + "@"
		}
	}

	link := fmt.Sprintf("%s://%s%s#%s",
		scheme,
		userpart,
		hostPort(server, port),
		fragment(name),
	)
	return link, true
}
