package input

import (
	"fmt"

	"github.com/openpaily/paily-fetch/node"
)

// parseTrojan parses a trojan:// link.
// Format: trojan://password@host:port?sni=&alpn=&fp=&allowInsecure=&type=&...#name
func parseTrojan(link string) (*node.ProxyNode, error) {
	u, name, err := parseStdURL(link)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("trojan URL missing password in userinfo")
	}
	password := u.User.Username()
	if password == "" {
		return nil, fmt.Errorf("trojan URL missing password in userinfo")
	}
	server := u.Hostname()
	port := portFromStr(u.Port())
	if server == "" || port == 0 {
		return nil, fmt.Errorf("trojan URL missing server or port")
	}

	q := u.Query()
	clash := map[string]any{
		"type":     "trojan",
		"name":     name,
		"server":   server,
		"port":     port,
		"password": password,
		"tls":      true, // Trojan always uses TLS
	}

	// SNI: prefer sni param, fall back to peer (older clients)
	sni := queryStr(q, "sni")
	if sni == "" {
		sni = queryStr(q, "peer")
	}
	if sni != "" {
		clash["sni"] = sni
	}
	if fp := queryStr(q, "fp"); fp != "" {
		clash["client-fingerprint"] = fp
	}
	if alpnRaw := queryStr(q, "alpn"); alpnRaw != "" {
		clash["alpn"] = splitALPN(alpnRaw)
	}
	if queryBool(q, "allowInsecure") || queryBool(q, "insecure") {
		clash["skip-cert-verify"] = true
	}

	// Reality support
	if queryStr(q, "security") == "reality" {
		ropts := map[string]any{}
		if pbk := queryStr(q, "pbk"); pbk != "" {
			ropts["public-key"] = pbk
		}
		if sid := queryStr(q, "sid"); sid != "" {
			ropts["short-id"] = sid
		}
		if len(ropts) > 0 {
			clash["reality-opts"] = ropts
		}
	}

	// Transport (ws / grpc)
	network := queryStr(q, "type")
	if network == "" {
		// Legacy ws params
		if queryStr(q, "ws") == "1" || queryStr(q, "obfs") == "websocket" {
			network = "ws"
		}
	}
	switch network {
	case "ws":
		applyWSParams(clash, q)
		// Legacy wspath param
		if clash["ws-opts"] == nil {
			if wspath := queryStr(q, "wspath"); wspath != "" {
				clash["ws-opts"] = map[string]any{"path": wspath}
			}
		}
	case "grpc":
		clash["network"] = "grpc"
		if svc := queryStr(q, "serviceName"); svc != "" {
			clash["grpc-opts"] = map[string]any{"grpc-service-name": svc}
		}
	}

	return node.New(clash)
}

// splitALPN splits an ALPN string that may be URL-encoded and comma-separated.
func splitALPN(raw string) []any {
	parts := splitDecoded(raw, ",")
	result := make([]any, len(parts))
	for i, p := range parts {
		result[i] = p
	}
	return result
}
