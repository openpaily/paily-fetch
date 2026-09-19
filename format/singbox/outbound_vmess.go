package singbox

// toSingboxVMess converts a clash VMess proxy map to a sing-box vmess outbound.
func toSingboxVMess(clash map[string]any, tag string) map[string]any {
	ob := map[string]any{
		"type":       "vmess",
		"tag":        tag,
		"server":     clashStr(clash, "server"),
		"server_port": clashInt(clash, "port"),
		"uuid":       clashStr(clash, "uuid"),
	}

	// alterId
	if aid := clashInt(clash, "alterId"); aid > 0 {
		ob["alter_id"] = aid
	}

	// cipher → security
	if cipher := clashStr(clash, "cipher"); cipher != "" && cipher != "auto" {
		ob["security"] = cipher
	} else {
		ob["security"] = "auto"
	}

	// TLS (VMess uses "servername" for SNI in clash)
	if tls := sbTLS(clash, "servername"); tls != nil {
		ob["tls"] = tls
	}

	// Transport
	if trans := sbTransport(clash); trans != nil {
		ob["transport"] = trans
	}

	return ob
}
