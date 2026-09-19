package input

import (
	"fmt"
	"strings"
	"time"

	"github.com/openpaily/paily-fetch/node"
)

// silentSkipTypes enumerates sing-box outbound types that are routing/management constructs
// and should be silently ignored (no log line emitted).
var silentSkipTypes = map[string]bool{
	"selector": true,
	"urltest":  true,
	"direct":   true,
	"block":    true,
	"dns":      true,
	"tun":      true,
	"tproxy":   true,
	"redirect": true,
}

// ParseSingbox parses a sing-box configuration map and returns ProxyNodes for all
// supported outbound entries. cfg is the entire decoded config map (e.g. from JSON).
// The function reads cfg["outbounds"]. Routing/management types are silently skipped.
// Unsupported proxy types and individual conversion failures are logged and skipped.
// A non-nil error is returned only when the "outbounds" field itself is malformed.
func ParseSingbox(cfg map[string]any) ([]*node.ProxyNode, error) {
	raw, ok := cfg["outbounds"]
	if !ok {
		return nil, nil
	}

	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("outbounds field is not a list")
	}

	nodes := make([]*node.ProxyNode, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			// log.Printf("[SKIP][input/singbox] #%d: entry is not a map", i)
			continue
		}

		sbType, _ := m["type"].(string)
		if silentSkipTypes[sbType] {
			continue
		}

		// Build a stable identifier for log messages.
		identifier, _ := m["tag"].(string)
		if identifier == "" {
			identifier = fmt.Sprintf("#%d", i)
		}

		clash, err := singboxOutboundToClash(m, sbType)
		if err != nil {
			// log.Printf("[SKIP][input/singbox] %s: %v", identifier, err)
			continue
		}

		n, err := node.New(clash)
		if err != nil {
			// log.Printf("[SKIP][input/singbox] %s: %v", identifier, err)
			continue
		}

		nodes = append(nodes, n)
	}

	return nodes, nil
}

// singboxOutboundToClash converts a sing-box outbound map to a clash proxy entry map.
// It returns an error for unsupported types or critically malformed entries.
func singboxOutboundToClash(m map[string]any, sbType string) (map[string]any, error) {
	tag, _ := m["tag"].(string)
	server, _ := m["server"].(string)
	port := int(sbFloat64(m["server_port"]))

	if server == "" {
		return nil, fmt.Errorf("missing server field")
	}
	if port == 0 {
		return nil, fmt.Errorf("missing or zero server_port field")
	}

	switch sbType {
	case "vmess":
		clash := map[string]any{
			"type":   "vmess",
			"name":   tag,
			"server": server,
			"port":   port,
		}
		clash["uuid"], _ = m["uuid"].(string)
		if aid, ok := m["alter_id"]; ok {
			clash["alterId"] = int(sbFloat64(aid))
		} else {
			clash["alterId"] = 0
		}
		cipher, _ := m["security"].(string)
		if cipher == "" {
			cipher = "auto"
		}
		clash["cipher"] = cipher
		if trans, ok := m["transport"].(map[string]any); ok {
			sbTransportToClash(clash, trans)
		}
		if tls, ok := m["tls"].(map[string]any); ok {
			sbTLSToClash(clash, tls, "servername")
		}
		return clash, nil

	case "vless":
		clash := map[string]any{
			"type":   "vless",
			"name":   tag,
			"server": server,
			"port":   port,
		}
		clash["uuid"], _ = m["uuid"].(string)
		if flow, _ := m["flow"].(string); flow != "" {
			clash["flow"] = flow
		}
		if pe, _ := m["packet_encoding"].(string); pe != "" {
			clash["packet-encoding"] = pe
		}
		if mux, ok := m["multiplex"].(map[string]any); ok {
			sbMultiplexToClash(clash, mux)
		}
		if trans, ok := m["transport"].(map[string]any); ok {
			sbTransportToClash(clash, trans)
		}
		if tls, ok := m["tls"].(map[string]any); ok {
			sbTLSToClash(clash, tls, "servername")
		}
		return clash, nil

	case "trojan":
		clash := map[string]any{
			"type":   "trojan",
			"name":   tag,
			"server": server,
			"port":   port,
		}
		clash["password"], _ = m["password"].(string)
		if trans, ok := m["transport"].(map[string]any); ok {
			sbTransportToClash(clash, trans)
		}
		if tls, ok := m["tls"].(map[string]any); ok {
			sbTLSToClash(clash, tls, "sni")
		}
		return clash, nil

	case "shadowsocks":
		clash := map[string]any{
			"type":   "ss",
			"name":   tag,
			"server": server,
			"port":   port,
		}
		method, _ := m["method"].(string)
		clash["cipher"] = method
		clash["password"], _ = m["password"].(string)
		// udp_over_tcp boolean
		if uot, _ := m["udp_over_tcp"].(bool); uot {
			clash["udp-over-tcp"] = true
		}
		// plugin
		if plugin, _ := m["plugin"].(string); plugin != "" {
			clashPlugin := plugin
			if plugin == "obfs-local" || plugin == "simple-obfs" {
				clashPlugin = "obfs"
			}
			clash["plugin"] = clashPlugin
			if opts, _ := m["plugin_opts"].(string); opts != "" {
				clash["plugin-opts"] = sbPluginOptsToClash(plugin, opts)
			}
		}
		return clash, nil

	case "hysteria":
		clash := map[string]any{
			"type":   "hysteria",
			"name":   tag,
			"server": server,
			"port":   port,
		}
		if authStr, _ := m["auth_str"].(string); authStr != "" {
			clash["auth-str"] = authStr
		} else if auth, _ := m["auth"].(string); auth != "" {
			// base64 encoded — store as auth-str; mihomo will accept it
			clash["auth-str"] = auth
		}
		if obfs, _ := m["obfs"].(string); obfs != "" {
			clash["obfs"] = obfs
		}
		if up, _ := m["up"].(string); up != "" {
			clash["up"] = up
		} else if upMbps := sbFloat64(m["up_mbps"]); upMbps > 0 {
			clash["up"] = fmt.Sprintf("%d Mbps", int(upMbps))
		}
		if down, _ := m["down"].(string); down != "" {
			clash["down"] = down
		} else if downMbps := sbFloat64(m["down_mbps"]); downMbps > 0 {
			clash["down"] = fmt.Sprintf("%d Mbps", int(downMbps))
		}
		if rw := sbFloat64(m["recv_window_conn"]); rw > 0 {
			clash["recv-window-conn"] = int(rw)
		}
		if rw := sbFloat64(m["recv_window"]); rw > 0 {
			clash["recv-window"] = int(rw)
		}
		if tls, ok := m["tls"].(map[string]any); ok {
			sbTLSToClash(clash, tls, "sni")
		}
		return clash, nil

	case "hysteria2":
		clash := map[string]any{
			"type":   "hysteria2",
			"name":   tag,
			"server": server,
			"port":   port,
		}
		clash["password"], _ = m["password"].(string)
		if obfsObj, ok := m["obfs"].(map[string]any); ok {
			if obfsType, _ := obfsObj["type"].(string); obfsType != "" {
				clash["obfs"] = obfsType
			}
			if obfsPass, _ := obfsObj["password"].(string); obfsPass != "" {
				clash["obfs-password"] = obfsPass
			}
		}
		if up, _ := m["up"].(string); up != "" {
			clash["up"] = up
		} else if upMbps := sbFloat64(m["up_mbps"]); upMbps > 0 {
			clash["up"] = fmt.Sprintf("%d Mbps", int(upMbps))
		}
		if down, _ := m["down"].(string); down != "" {
			clash["down"] = down
		} else if downMbps := sbFloat64(m["down_mbps"]); downMbps > 0 {
			clash["down"] = fmt.Sprintf("%d Mbps", int(downMbps))
		}
		// port hopping: singbox ["443:8443"] → mihomo "443-8443"
		if ports, ok := m["server_ports"].([]any); ok && len(ports) > 0 {
			ranges := make([]string, 0, len(ports))
			for _, p := range ports {
				if s, ok := p.(string); ok {
					ranges = append(ranges, strings.ReplaceAll(s, ":", "-"))
				}
			}
			if len(ranges) > 0 {
				clash["ports"] = strings.Join(ranges, ",")
			}
		}
		if tls, ok := m["tls"].(map[string]any); ok {
			sbTLSToClash(clash, tls, "sni")
		}
		return clash, nil

	case "tuic":
		clash := map[string]any{
			"type":   "tuic",
			"name":   tag,
			"server": server,
			"port":   port,
		}
		clash["uuid"], _ = m["uuid"].(string)
		clash["password"], _ = m["password"].(string)
		if cc, _ := m["congestion_control"].(string); cc != "" {
			clash["congestion-controller"] = cc
		}
		if udpMode, _ := m["udp_relay_mode"].(string); udpMode != "" {
			clash["udp-relay-mode"] = udpMode
		}
		if zeroRTT, _ := m["zero_rtt_handshake"].(bool); zeroRTT {
			clash["reduce-rtt"] = true
		}
		if tls, ok := m["tls"].(map[string]any); ok {
			sbTLSToClash(clash, tls, "sni")
		}
		return clash, nil

	case "socks":
		clash := map[string]any{
			"type":   "socks5",
			"name":   tag,
			"server": server,
			"port":   port,
		}
		if user, _ := m["username"].(string); user != "" {
			clash["username"] = user
		}
		if pass, _ := m["password"].(string); pass != "" {
			clash["password"] = pass
		}
		return clash, nil

	case "http":
		clash := map[string]any{
			"type":   "http",
			"name":   tag,
			"server": server,
			"port":   port,
		}
		if user, _ := m["username"].(string); user != "" {
			clash["username"] = user
		}
		if pass, _ := m["password"].(string); pass != "" {
			clash["password"] = pass
		}
		if tls, ok := m["tls"].(map[string]any); ok {
			sbTLSToClash(clash, tls, "sni")
		}
		return clash, nil

	case "anytls":
		clash := map[string]any{
			"type":   "anytls",
			"name":   tag,
			"server": server,
			"port":   port,
		}
		clash["password"], _ = m["password"].(string)
		if tls, ok := m["tls"].(map[string]any); ok {
			sbTLSToClash(clash, tls, "sni")
		}
		if interval, _ := m["idle_session_check_interval"].(string); interval != "" {
			if secs := sbDurationSeconds(interval); secs > 0 {
				clash["idle-session-check-interval"] = secs
			}
		}
		return clash, nil

	default:
		return nil, fmt.Errorf("unsupported outbound type %q", sbType)
	}
}

// sbTLSToClash extracts TLS fields from a sing-box tls object and merges them into clash.
// sniKey is "servername" for VMess/VLESS, "sni" for all other protocols.
func sbTLSToClash(clash, tls map[string]any, sniKey string) {
	if enabled, _ := tls["enabled"].(bool); enabled {
		clash["tls"] = true
	}
	if sn, _ := tls["server_name"].(string); sn != "" {
		clash[sniKey] = sn
	}
	if insecure, _ := tls["insecure"].(bool); insecure {
		clash["skip-cert-verify"] = true
	}
	if alpn, _ := tls["alpn"].([]any); len(alpn) > 0 {
		clash["alpn"] = alpn
	}
	if utls, ok := tls["utls"].(map[string]any); ok {
		if fp, _ := utls["fingerprint"].(string); fp != "" {
			clash["client-fingerprint"] = fp
		}
	}
	if ech, ok := tls["ech"].(map[string]any); ok {
		if config, ok := ech["config"].([]any); ok && len(config) > 0 {
			parts := make([]string, 0, len(config))
			for _, raw := range config {
				if s, ok := raw.(string); ok && s != "" {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				clash["ech"] = strings.Join(parts, ",")
			}
		}
	}
	if reality, ok := tls["reality"].(map[string]any); ok {
		if enabled, _ := reality["enabled"].(bool); enabled {
			ropts := map[string]any{}
			if pk, _ := reality["public_key"].(string); pk != "" {
				ropts["public-key"] = pk
			}
			if sid, _ := reality["short_id"].(string); sid != "" {
				ropts["short-id"] = sid
			}
			if len(ropts) > 0 {
				clash["reality-opts"] = ropts
			}
		}
	}
}

// sbTransportToClash extracts transport fields from a sing-box transport object and
// merges the resulting clash network/opts fields into clash.
func sbTransportToClash(clash, trans map[string]any) {
	ttype, _ := trans["type"].(string)
	switch ttype {
	case "ws":
		clash["network"] = "ws"
		wsOpts := map[string]any{}
		if path, _ := trans["path"].(string); path != "" {
			wsOpts["path"] = path
		}
		if headers, ok := trans["headers"].(map[string]any); ok && len(headers) > 0 {
			wsOpts["headers"] = headers
		}
		if maxED := sbFloat64(trans["max_early_data"]); maxED > 0 {
			wsOpts["max-early-data"] = int(maxED)
		}
		if edhName, _ := trans["early_data_header_name"].(string); edhName != "" {
			wsOpts["early-data-header-name"] = edhName
		}
		if len(wsOpts) > 0 {
			clash["ws-opts"] = wsOpts
		}

	case "http":
		// sing-box http transport → mihomo h2 (HTTP/2)
		clash["network"] = "h2"
		h2Opts := map[string]any{}
		if hosts, ok := trans["host"].([]any); ok && len(hosts) > 0 {
			h2Opts["host"] = hosts
		}
		if path, _ := trans["path"].(string); path != "" {
			h2Opts["path"] = path
		}
		if len(h2Opts) > 0 {
			clash["h2-opts"] = h2Opts
		}

	case "grpc":
		clash["network"] = "grpc"
		grpcOpts := map[string]any{}
		if svc, _ := trans["service_name"].(string); svc != "" {
			grpcOpts["grpc-service-name"] = svc
		}
		if authority, _ := trans["authority"].(string); authority != "" {
			grpcOpts["grpc-authority"] = authority
		}
		if mode, _ := trans["mode"].(string); mode != "" {
			grpcOpts["grpc-mode"] = mode
		}
		if len(grpcOpts) > 0 {
			clash["grpc-opts"] = grpcOpts
		}

	case "httpupgrade":
		// sing-box httpupgrade → mihomo ws with v2ray-http-upgrade flag
		clash["network"] = "ws"
		wsOpts := map[string]any{"v2ray-http-upgrade": true}
		if path, _ := trans["path"].(string); path != "" {
			wsOpts["path"] = path
		}
		headers := map[string]any{}
		if host, _ := trans["host"].(string); host != "" {
			headers["Host"] = host
		}
		if hdrs, ok := trans["headers"].(map[string]any); ok {
			for k, v := range hdrs {
				headers[k] = v
			}
		}
		if len(headers) > 0 {
			wsOpts["headers"] = headers
		}
		clash["ws-opts"] = wsOpts

	case "quic":
		clash["network"] = "quic"
	}
}

func sbMultiplexToClash(clash, mux map[string]any) {
	if enabled, _ := mux["enabled"].(bool); !enabled {
		return
	}
	smux := map[string]any{"enabled": true}
	if protocol, _ := mux["protocol"].(string); protocol != "" {
		smux["protocol"] = protocol
	}
	if maxConnections := sbFloat64(mux["max_connections"]); maxConnections > 0 {
		smux["max-connections"] = int(maxConnections)
	}
	if minStreams := sbFloat64(mux["min_streams"]); minStreams > 0 {
		smux["min-streams"] = int(minStreams)
	}
	if maxStreams := sbFloat64(mux["max_streams"]); maxStreams > 0 {
		smux["max-streams"] = int(maxStreams)
	}
	if padding, _ := mux["padding"].(bool); padding {
		smux["padding"] = true
	}
	if brutal, ok := mux["brutal"].(map[string]any); ok {
		brutalOpts := map[string]any{}
		if enabled, _ := brutal["enabled"].(bool); enabled {
			brutalOpts["enabled"] = true
		}
		if up := sbFloat64(brutal["up_mbps"]); up > 0 {
			brutalOpts["up"] = int(up)
		}
		if down := sbFloat64(brutal["down_mbps"]); down > 0 {
			brutalOpts["down"] = int(down)
		}
		if len(brutalOpts) > 0 {
			smux["brutal-opts"] = brutalOpts
		}
	}
	clash["smux"] = smux
}

// sbPluginOptsToClash parses a sing-box plugin_opts semicolon-delimited string and
// converts it to a mihomo-style plugin-opts map.
func sbPluginOptsToClash(plugin, opts string) map[string]any {
	raw := map[string]any{}
	for _, part := range strings.Split(opts, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx := strings.IndexByte(part, '='); idx >= 0 {
			raw[part[:idx]] = part[idx+1:]
		} else {
			raw[part] = true
		}
	}

	// Remap obfs-local / simple-obfs opts to mihomo clash format.
	if plugin == "obfs-local" || plugin == "simple-obfs" {
		mapped := map[string]any{}
		if v, ok := raw["obfs"]; ok {
			mapped["mode"] = v
		}
		if v, ok := raw["obfs-host"]; ok {
			mapped["host"] = v
		}
		return mapped
	}

	// For v2ray-plugin: promote host into headers map.
	if plugin == "v2ray-plugin" {
		if host, ok := raw["host"].(string); ok && host != "" {
			raw["headers"] = map[string]any{"Host": host}
			delete(raw, "host")
		}
	}

	return raw
}

// sbDurationSeconds parses a sing-box duration string (e.g. "30s", "1m", "500ms")
// and returns the equivalent value in whole seconds. Returns 0 on parse failure.
func sbDurationSeconds(s string) int {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return int(d.Seconds())
}

// sbFloat64 safely coerces an any value to float64, returning 0 for non-numeric types.
// JSON decode produces float64 for all numbers; YAML decode may produce int/int64.
func sbFloat64(v any) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case float32:
		return float64(val)
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case int32:
		return float64(val)
	case uint:
		return float64(val)
	case uint64:
		return float64(val)
	}
	return 0
}
