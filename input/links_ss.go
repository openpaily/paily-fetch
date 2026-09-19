package input

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/openpaily/paily-fetch/node"
)

// parseSS parses a ss:// link.
// Supports:
//   - SIP002:      ss://base64(method:password)@host:port[?plugin=...]#name
//   - SIP002 plain: ss://method:password@host:port[?plugin=...]#name
//   - Legacy:      ss://base64(method:password@host:port)#name
func parseSS(link string) ([]*node.ProxyNode, error) {
	raw := link[len("ss://"):]

	// Separate fragment (name)
	name := ""
	if idx := strings.IndexByte(raw, '#'); idx >= 0 {
		fragEncoded := raw[idx+1:]
		decoded, err := url.QueryUnescape(fragEncoded)
		if err == nil {
			name = decoded
		} else {
			name = fragEncoded
		}
		raw = raw[:idx]
	}

	// If raw contains '@', it's SIP002 (modern format)
	if strings.Contains(raw, "@") {
		n, err := parseSIP002(raw, name)
		if err != nil {
			return nil, err
		}
		return []*node.ProxyNode{n}, nil
	}

	// Legacy base64: ss://base64(method:password@host:port)
	n, err := parseLegacySS(raw, name)
	if err != nil {
		return nil, err
	}
	return []*node.ProxyNode{n}, nil
}

// parseSIP002 parses the SIP002 format: base64-or-plain-userinfo@host:port[?plugin=...]
func parseSIP002(raw, name string) (*node.ProxyNode, error) {
	// raw is the link without ss:// prefix and without fragment
	// May have ?plugin=... query
	query := ""
	if idx := strings.IndexByte(raw, '?'); idx >= 0 {
		query = raw[idx+1:]
		raw = raw[:idx]
	}

	atIdx := strings.LastIndex(raw, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("ss SIP002 missing '@'")
	}
	userinfo := raw[:atIdx]
	hostPort := raw[atIdx+1:]

	host, portStr, err := splitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("ss SIP002 invalid host:port: %w", err)
	}
	port := portFromStr(portStr)
	if port == 0 {
		return nil, fmt.Errorf("ss SIP002 invalid port %q", portStr)
	}

	// Decode userinfo: may be base64 or plain method:password
	method, password, err := decodeSSUserinfo(userinfo)
	if err != nil {
		return nil, err
	}

	if name == "" {
		name = host + ":" + portStr
	}
	clash := map[string]any{
		"type":     "ss",
		"name":     name,
		"server":   host,
		"port":     port,
		"cipher":   method,
		"password": password,
	}

	// Parse plugin from query
	if query != "" {
		q, err := url.ParseQuery(query)
		if err == nil {
			applySSPlugin(clash, q)
		}
	}

	return node.New(clash)
}

// parseLegacySS parses legacy ss://base64(method:password@host:port) format.
func parseLegacySS(raw, name string) (*node.ProxyNode, error) {
	// Strip possible query
	if idx := strings.IndexByte(raw, '?'); idx >= 0 {
		raw = raw[:idx]
	}
	decoded, err := base64Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("ss legacy base64 decode failed: %w", err)
	}
	// Decoded: method:password@host:port
	atIdx := strings.LastIndex(decoded, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("ss legacy decoded string missing '@'")
	}
	cipherPart := decoded[:atIdx]
	hostPort := decoded[atIdx+1:]

	host, portStr, err := splitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("ss legacy invalid host:port: %w", err)
	}
	port := portFromStr(portStr)
	if port == 0 {
		return nil, fmt.Errorf("ss legacy invalid port %q", portStr)
	}

	// cipherPart = method:password
	colonIdx := strings.IndexByte(cipherPart, ':')
	if colonIdx < 0 {
		return nil, fmt.Errorf("ss legacy missing ':' in cipher:password")
	}
	method := cipherPart[:colonIdx]
	password := cipherPart[colonIdx+1:]

	if name == "" {
		name = host + ":" + portStr
	}

	clash := map[string]any{
		"type":     "ss",
		"name":     name,
		"server":   host,
		"port":     port,
		"cipher":   method,
		"password": password,
	}
	return node.New(clash)
}

// parseSSD parses ssd://base64(json) format.
func parseSSD(link string) ([]*node.ProxyNode, error) {
	raw := link[len("ssd://"):]
	decoded, err := base64Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("ssd base64 decode failed: %w", err)
	}

	var obj map[string]any
	if err := json.Unmarshal([]byte(decoded), &obj); err != nil {
		return nil, fmt.Errorf("ssd JSON parse failed: %w", err)
	}

	method, _ := obj["encryption"].(string)
	password, _ := obj["password"].(string)
	portFloat := sbFloat64(obj["port"])
	port := int(portFloat)

	servers, _ := obj["servers"].([]any)
	if len(servers) == 0 {
		return nil, fmt.Errorf("ssd JSON has no 'servers' field")
	}

	var nodes []*node.ProxyNode
	for _, s := range servers {
		srv, ok := s.(map[string]any)
		if !ok {
			continue
		}
		host, _ := srv["server"].(string)
		if host == "" {
			continue
		}
		srvPort := int(sbFloat64(srv["port"]))
		if srvPort == 0 {
			srvPort = port
		}
		srvMethod := method
		if m, _ := srv["encryption"].(string); m != "" {
			srvMethod = m
		}
		srvPass := password
		if p, _ := srv["password"].(string); p != "" {
			srvPass = p
		}
		name, _ := srv["remarks"].(string)
		if name == "" {
			name = host
		}

		clash := map[string]any{
			"type":     "ss",
			"name":     name,
			"server":   host,
			"port":     srvPort,
			"cipher":   srvMethod,
			"password": srvPass,
		}
		n, err := node.New(clash)
		if err != nil {
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// ─── SS helpers ──────────────────────────────────────────────────────────────

// decodeSSUserinfo decodes the userinfo part of a SIP002 link.
// It may be plain "method:password" or base64("method:password").
func decodeSSUserinfo(userinfo string) (method, password string, err error) {
	if strings.Contains(userinfo, ":") {
		// Plain
		idx := strings.IndexByte(userinfo, ':')
		return userinfo[:idx], userinfo[idx+1:], nil
	}
	// Try base64
	decoded, derr := base64Decode(userinfo)
	if derr != nil {
		return "", "", fmt.Errorf("ss userinfo neither plain nor valid base64: %w", derr)
	}
	idx := strings.IndexByte(decoded, ':')
	if idx < 0 {
		return "", "", fmt.Errorf("ss userinfo decoded string missing ':'")
	}
	return decoded[:idx], decoded[idx+1:], nil
}

// applySSPlugin reads the plugin query param and writes plugin / plugin-opts to clash.
func applySSPlugin(clash map[string]any, q url.Values) {
	plugin := q.Get("plugin")
	if plugin == "" {
		return
	}

	// plugin = "pluginName;param1=val1;..."
	parts := strings.SplitN(plugin, ";", 2)
	pluginName := parts[0]
	if pluginName == "obfs-local" || pluginName == "simple-obfs" {
		pluginName = "obfs"
	}
	clash["plugin"] = pluginName

	if len(parts) == 2 && parts[1] != "" {
		opts := map[string]any{}
		for _, kv := range strings.Split(parts[1], ";") {
			if idx := strings.IndexByte(kv, '='); idx >= 0 {
				k, v := kv[:idx], kv[idx+1:]
				// Remap obfs-local keys
				switch k {
				case "obfs":
					opts["mode"] = v
				case "obfs-host":
					opts["host"] = v
				default:
					opts[k] = v
				}
			}
		}
		if len(opts) > 0 {
			clash["plugin-opts"] = opts
		}
	}
}

// base64Decode tries standard then URL-safe decoding, tolerating missing padding.
func base64Decode(s string) (string, error) {
	s = strings.TrimRight(s, "=")
	if rem := len(s) % 4; rem != 0 {
		s += strings.Repeat("=", 4-rem)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return "", err
		}
	}
	return string(b), nil
}

// splitHostPort splits "host:port" handling IPv6 brackets.
func splitHostPort(hostPort string) (host, port string, err error) {
	if strings.HasPrefix(hostPort, "[") {
		end := strings.LastIndex(hostPort, "]")
		if end < 0 {
			return "", "", fmt.Errorf("unclosed IPv6 bracket in %q", hostPort)
		}
		host = hostPort[1:end]
		rest := hostPort[end+1:]
		if strings.HasPrefix(rest, ":") {
			port = rest[1:]
		}
		return
	}
	idx := strings.LastIndexByte(hostPort, ':')
	if idx < 0 {
		return hostPort, "", nil
	}
	return hostPort[:idx], hostPort[idx+1:], nil
}

// splitDecoded splits a possibly URL-encoded string by sep after decoding.
func splitDecoded(s, sep string) []string {
	decoded, err := url.QueryUnescape(s)
	if err == nil {
		s = decoded
	}
	return strings.Split(s, sep)
}
