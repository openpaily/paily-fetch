package singbox

// toSingboxHysteria2 converts a clash Hysteria2 proxy map to a sing-box hysteria2 outbound.
func toSingboxHysteria2(clash map[string]any, tag string) map[string]any {
	ob := map[string]any{
		"type":        "hysteria2",
		"tag":         tag,
		"server":      clashStr(clash, "server"),
		"server_port": clashInt(clash, "port"),
		"password":    clashStr(clash, "password"),
	}

	// OBFS — clash: obfs (type string) + obfs-password; singbox: obfs object
	if obfsType := clashStr(clash, "obfs"); obfsType != "" {
		obfsObj := map[string]any{"type": obfsType}
		if obfsPass := clashStr(clash, "obfs-password"); obfsPass != "" {
			obfsObj["password"] = obfsPass
		}
		ob["obfs"] = obfsObj
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

	// Port hopping
	if ports := clashStr(clash, "ports"); ports != "" {
		ob["server_ports"] = ports // singbox 1.10+ uses server_ports for hy2 port hopping
	}

	// TLS (Hysteria2 always uses TLS)
	ob["tls"] = sbTLSAlways(clash, "sni")

	return ob
}
