package singbox

// toSingboxHysteria converts a clash Hysteria V1 proxy map to a sing-box hysteria outbound.
// The caller has already filtered out wechat-video obfs and faketcp protocol.
func toSingboxHysteria(clash map[string]any, tag string) map[string]any {
	ob := map[string]any{
		"type":        "hysteria",
		"tag":         tag,
		"server":      clashStr(clash, "server"),
		"server_port": clashInt(clash, "port"),
	}

	if authStr := clashStr(clash, "auth-str"); authStr != "" {
		ob["auth_str"] = authStr
	}

	if up := clashStr(clash, "up"); up != "" {
		if n := parseMbps(up); n > 0 {
			ob["up_mbps"] = n
		}
	}
	if down := clashStr(clash, "down"); down != "" {
		if n := parseMbps(down); n > 0 {
			ob["down_mbps"] = n
		}
	}

	if obfs := clashStr(clash, "obfs"); obfs != "" {
		ob["obfs"] = obfs
	}

	// Port hopping
	if ports := clashStr(clash, "ports"); ports != "" {
		ob["ports"] = ports
	}

	// TLS (Hysteria always uses TLS)
	ob["tls"] = sbTLSAlways(clash, "sni")

	return ob
}
