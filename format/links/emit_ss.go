package links

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// emitSS generates a ss:// SIP002 link.
func emitSS(clash map[string]any, name string) (string, bool) {
	server := lStr(clash, "server")
	port := lInt(clash, "port")
	cipher := lStr(clash, "cipher")
	password := lStr(clash, "password")
	if server == "" || port == 0 || cipher == "" || password == "" {
		return "", false
	}

	// SIP002: ss://BASE64(method:password)@host:port[/][?plugin=...]#name
	userinfo := base64.StdEncoding.EncodeToString([]byte(cipher + ":" + password))
	link := fmt.Sprintf("ss://%s@%s", userinfo, hostPort(server, port))

	q := url.Values{}
	plugin := lStr(clash, "plugin")
	if plugin != "" {
		opts := lMap(clash, "plugin-opts")
		pluginStr := plugin
		if opts != nil {
			parts := []string{plugin}
			for k, v := range opts {
				parts = append(parts, fmt.Sprintf("%s=%v", k, v))
			}
			pluginStr = strings.Join(parts, ";")
		}
		q.Set("plugin", pluginStr)
	}
	if len(q) > 0 {
		link += "?" + q.Encode()
	}
	link += "#" + fragment(name)
	return link, true
}

// emitSSR generates an ssr:// link.
func emitSSR(clash map[string]any, name string) (string, bool) {
	server := lStr(clash, "server")
	port := lInt(clash, "port")
	cipher := lStr(clash, "cipher")
	password := lStr(clash, "password")
	protocol := lStr(clash, "protocol")
	obfs := lStr(clash, "obfs")
	if server == "" || port == 0 || cipher == "" || password == "" {
		return "", false
	}
	if protocol == "" {
		protocol = "origin"
	}
	if obfs == "" {
		obfs = "plain"
	}

	passB64 := base64.RawURLEncoding.EncodeToString([]byte(password))

	// ssr://host:port:protocol:cipher:obfs:base64pass
	core := fmt.Sprintf("%s:%d:%s:%s:%s:%s",
		server, port, protocol, cipher, obfs, passB64,
	)

	q := url.Values{}
	q.Set("remarks", base64.RawURLEncoding.EncodeToString([]byte(name)))
	if obfsParam := lStr(clash, "obfs-param"); obfsParam != "" {
		q.Set("obfsparam", base64.RawURLEncoding.EncodeToString([]byte(obfsParam)))
	}
	if protoParam := lStr(clash, "protocol-param"); protoParam != "" {
		q.Set("protoparam", base64.RawURLEncoding.EncodeToString([]byte(protoParam)))
	}
	full := core + "/?" + q.Encode()
	encoded := base64.RawURLEncoding.EncodeToString([]byte(full))
	return "ssr://" + encoded, true
}
