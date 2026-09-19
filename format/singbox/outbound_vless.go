package singbox

// toSingboxVLESS converts a clash VLESS proxy map to a sing-box vless outbound.
// Only fields that have a sing-box equivalent are emitted.
func toSingboxVLESS(clash map[string]any, tag string) map[string]any {
	ob := map[string]any{
		"type":        "vless",
		"tag":         tag,
		"server":      clashStr(clash, "server"),
		"server_port": clashInt(clash, "port"),
		"uuid":        clashStr(clash, "uuid"),
	}

	if flow := clashStr(clash, "flow"); flow != "" {
		ob["flow"] = flow
	}
	if pe := clashStr(clash, "packet-encoding"); pe != "" {
		ob["packet_encoding"] = pe
	}

	// TLS (VLESS uses "servername" for SNI in clash)
	if tls := sbTLS(clash, "servername"); tls != nil {
		ob["tls"] = tls
	}

	if mux := sbMultiplex(clash); mux != nil {
		ob["multiplex"] = mux
	}

	// Transport
	if trans := sbTransport(clash); trans != nil {
		ob["transport"] = trans
	}

	return ob
}
