package singbox

// toSingboxTUIC converts a clash TUIC V5 proxy map to a sing-box tuic outbound.
// The caller has already filtered out TUIC V4 (token-only) entries.
func toSingboxTUIC(clash map[string]any, tag string) map[string]any {
	ob := map[string]any{
		"type":        "tuic",
		"tag":         tag,
		"server":      clashStr(clash, "server"),
		"server_port": clashInt(clash, "port"),
		"uuid":        clashStr(clash, "uuid"),
		"password":    clashStr(clash, "password"),
	}

	// clash: congestion-controller → singbox: congestion_control
	if cc := clashStr(clash, "congestion-controller"); cc != "" {
		ob["congestion_control"] = cc
	}

	// clash: udp-relay-mode → singbox: udp_relay_mode
	if udpMode := clashStr(clash, "udp-relay-mode"); udpMode != "" {
		ob["udp_relay_mode"] = udpMode
	}

	// TLS (TUIC always uses TLS)
	ob["tls"] = sbTLSAlways(clash, "sni")

	return ob
}
