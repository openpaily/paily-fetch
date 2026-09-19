package singbox

import (
	"strconv"
	"strings"
)

// ─── clash map accessors ──────────────────────────────────────────────────────

// clashStr returns the string value for key in m, or "" if absent or wrong type.
func clashStr(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// clashInt returns the int value for key in m, handling int/float64/string types.
func clashInt(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}

// clashBool returns the bool value for key in m.
func clashBool(m map[string]any, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	}
	return false
}

// clashStringSlice converts a clash []any or []string value to []string.
func clashStringSlice(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch val := v.(type) {
	case []string:
		return val
	case []any:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// clashMap returns the map[string]any value for key, or nil.
func clashMap(m map[string]any, key string) map[string]any {
	v, ok := m[key]
	if !ok {
		return nil
	}
	sub, _ := v.(map[string]any)
	return sub
}

// ─── TLS / transport helpers ──────────────────────────────────────────────────

// sbTLS builds a sing-box tls object from a clash proxy map.
// sniKey is the clash field name for SNI ("servername" for VMess/VLESS, "sni" for others).
// Returns nil if TLS is disabled (clash "tls" is not true).
func sbTLS(clash map[string]any, sniKey string) map[string]any {
	if !clashBool(clash, "tls") {
		return nil
	}
	tls := map[string]any{"enabled": true}

	if sni := clashStr(clash, sniKey); sni != "" {
		tls["server_name"] = sni
	}
	if clashBool(clash, "skip-cert-verify") {
		tls["insecure"] = true
	}
	if alpn := clashStringSlice(clash, "alpn"); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if fp := clashStr(clash, "client-fingerprint"); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if ech := clashStr(clash, "ech"); ech != "" {
		tls["ech"] = map[string]any{"enabled": true, "config": []string{ech}}
	}
	// Reality options
	if ro := clashMap(clash, "reality-opts"); ro != nil {
		reality := map[string]any{"enabled": true}
		if pbk := clashStr(ro, "public-key"); pbk != "" {
			reality["public_key"] = pbk
		}
		if sid := clashStr(ro, "short-id"); sid != "" {
			reality["short_id"] = sid
		}
		if len(reality) > 0 {
			tls["reality"] = reality
		}
	}
	return tls
}

// sbTLSAlways is like sbTLS but forces TLS enabled regardless of the "tls" field.
// Used for protocols that always use TLS (Trojan, TUIC, Hysteria, AnyTLS).
func sbTLSAlways(clash map[string]any, sniKey string) map[string]any {
	original := clash["tls"]
	clash["tls"] = true
	result := sbTLS(clash, sniKey)
	if original != nil {
		clash["tls"] = original
	} else {
		delete(clash, "tls")
	}
	return result
}

// sbTransport builds a sing-box transport object from clash network/opts fields.
// Returns nil if network is empty or "tcp".
func sbTransport(clash map[string]any) map[string]any {
	network := clashStr(clash, "network")
	switch network {
	case "ws":
		t := map[string]any{"type": "ws"}
		if wsOpts := clashMap(clash, "ws-opts"); wsOpts != nil {
			if upgrade, _ := wsOpts["v2ray-http-upgrade"].(bool); upgrade {
				t["type"] = "httpupgrade"
			}
			if path := clashStr(wsOpts, "path"); path != "" {
				t["path"] = path
			}
			if hdrs := clashMap(wsOpts, "headers"); hdrs != nil {
				copied := map[string]any{}
				for k, v := range hdrs {
					if t["type"] == "httpupgrade" && strings.EqualFold(k, "Host") {
						if host, ok := v.(string); ok && host != "" {
							t["host"] = host
						}
						continue
					}
					copied[k] = v
				}
				if len(copied) > 0 {
					t["headers"] = copied
				}
			}
		}
		return t

	case "h2":
		t := map[string]any{"type": "http"}
		if h2Opts := clashMap(clash, "h2-opts"); h2Opts != nil {
			if path := clashStr(h2Opts, "path"); path != "" {
				t["path"] = path
			}
			if hosts := clashStringSlice(h2Opts, "host"); len(hosts) > 0 {
				t["host"] = hosts
			}
		}
		return t

	case "grpc":
		t := map[string]any{"type": "grpc"}
		if grpcOpts := clashMap(clash, "grpc-opts"); grpcOpts != nil {
			if svc := clashStr(grpcOpts, "grpc-service-name"); svc != "" {
				t["service_name"] = svc
			}
			if authority := clashStr(grpcOpts, "grpc-authority"); authority != "" {
				t["authority"] = authority
			}
			if mode := clashStr(grpcOpts, "grpc-mode"); mode != "" {
				t["mode"] = mode
			}
		}
		return t

	case "quic":
		t := map[string]any{"type": "quic"}
		return t

	default:
		return nil
	}
}

func sbMultiplex(clash map[string]any) map[string]any {
	smux := clashMap(clash, "smux")
	if smux == nil || !clashBool(smux, "enabled") {
		return nil
	}
	mux := map[string]any{"enabled": true}
	if protocol := clashStr(smux, "protocol"); protocol != "" {
		mux["protocol"] = protocol
	}
	if maxConnections := clashInt(smux, "max-connections"); maxConnections > 0 {
		mux["max_connections"] = maxConnections
	}
	if minStreams := clashInt(smux, "min-streams"); minStreams > 0 {
		mux["min_streams"] = minStreams
	}
	if maxStreams := clashInt(smux, "max-streams"); maxStreams > 0 {
		mux["max_streams"] = maxStreams
	}
	if clashBool(smux, "padding") {
		mux["padding"] = true
	}
	if brutalOpts := clashMap(smux, "brutal-opts"); brutalOpts != nil && clashBool(brutalOpts, "enabled") {
		brutal := map[string]any{"enabled": true}
		if up := clashInt(brutalOpts, "up"); up > 0 {
			brutal["up_mbps"] = up
		}
		if down := clashInt(brutalOpts, "down"); down > 0 {
			brutal["down_mbps"] = down
		}
		mux["brutal"] = brutal
	}
	return mux
}

// ─── mbps parsing ─────────────────────────────────────────────────────────────

// parseMbps parses a bandwidth string like "10 Mbps", "10mbps", or "10" to int.
func parseMbps(s string) int {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(strings.ToLower(s), " mbps")
	s = strings.TrimSuffix(s, "mbps")
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return int(f)
	}
	return 0
}
