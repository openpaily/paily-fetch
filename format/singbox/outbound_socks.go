package singbox

// toSingboxSOCKS converts a clash socks5 proxy map to a sing-box socks outbound.
func toSingboxSOCKS(clash map[string]any, tag string) map[string]any {
	ob := map[string]any{
		"type":        "socks",
		"tag":         tag,
		"server":      clashStr(clash, "server"),
		"server_port": clashInt(clash, "port"),
		"version":     "5",
	}

	if user := clashStr(clash, "username"); user != "" {
		ob["username"] = user
	}
	if pass := clashStr(clash, "password"); pass != "" {
		ob["password"] = pass
	}

	return ob
}
