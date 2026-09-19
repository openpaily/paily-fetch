package singbox

// toSingboxAnyTLS converts a clash anytls proxy map to a sing-box anytls outbound.
// AnyTLS is supported in sing-box 1.12+.
func toSingboxAnyTLS(clash map[string]any, tag string) map[string]any {
	ob := map[string]any{
		"type":        "anytls",
		"tag":         tag,
		"server":      clashStr(clash, "server"),
		"server_port": clashInt(clash, "port"),
		"password":    clashStr(clash, "password"),
	}

	// AnyTLS always uses TLS
	ob["tls"] = sbTLSAlways(clash, "sni")

	return ob
}
