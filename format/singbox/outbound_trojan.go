package singbox

// toSingboxTrojan converts a clash Trojan proxy map to a sing-box trojan outbound.
// Trojan always enables TLS; the caller has already filtered out ss-opts entries.
func toSingboxTrojan(clash map[string]any, tag string) map[string]any {
	ob := map[string]any{
		"type":        "trojan",
		"tag":         tag,
		"server":      clashStr(clash, "server"),
		"server_port": clashInt(clash, "port"),
		"password":    clashStr(clash, "password"),
	}

	// Trojan always has TLS; use sbTLSAlways to force enabled=true
	// even if clash map has tls:false (shouldn't happen for trojan, but be safe)
	ob["tls"] = sbTLSAlways(clash, "sni")

	// Transport (Trojan over WS / gRPC is supported in clash and sing-box)
	if trans := sbTransport(clash); trans != nil {
		ob["transport"] = trans
	}

	return ob
}
