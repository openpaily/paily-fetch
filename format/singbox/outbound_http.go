package singbox

// toSingboxHTTP converts a clash http proxy map to a sing-box http outbound.
func toSingboxHTTP(clash map[string]any, tag string) map[string]any {
	ob := map[string]any{
		"type":        "http",
		"tag":         tag,
		"server":      clashStr(clash, "server"),
		"server_port": clashInt(clash, "port"),
	}

	if user := clashStr(clash, "username"); user != "" {
		ob["username"] = user
	}
	if pass := clashStr(clash, "password"); pass != "" {
		ob["password"] = pass
	}

	// TLS: only if tls: true in clash (HTTPS proxy)
	if tls := sbTLS(clash, "sni"); tls != nil {
		ob["tls"] = tls
	}

	return ob
}
