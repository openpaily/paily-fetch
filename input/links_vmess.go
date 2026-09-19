package input

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/openpaily/paily-fetch/node"
)

// parseVMess parses a vmess:// link.
// Supports the V2RayN base64-JSON format and the standard vmess://uuid@host:port?... URL.
func parseVMess(link string) (*node.ProxyNode, error) {
	raw := link[len("vmess://"):]

	// Detect standard URL format: contains "@" after optional stripping of fragment
	withoutFrag := raw
	if idx := strings.IndexByte(raw, '#'); idx >= 0 {
		withoutFrag = raw[:idx]
	}

	if strings.Contains(withoutFrag, "@") {
		return parseVMessURL(link)
	}

	// Try to base64-decode and parse as JSON
	// Normalise padding and handle URL-safe encoding
	padded := raw
	if idx := strings.IndexByte(padded, '#'); idx >= 0 {
		padded = padded[:idx]
	}
	padded = strings.TrimRight(padded, "=")
	// Pad to multiple of 4
	if rem := len(padded) % 4; rem != 0 {
		padded += strings.Repeat("=", 4-rem)
	}

	decoded, err := base64.StdEncoding.DecodeString(padded)
	if err != nil {
		// Try URL-safe encoding
		decoded, err = base64.URLEncoding.DecodeString(padded)
		if err != nil {
			return nil, fmt.Errorf("vmess base64 decode failed: %w", err)
		}
	}

	var obj map[string]any
	if err := json.Unmarshal(decoded, &obj); err != nil {
		return nil, fmt.Errorf("vmess JSON parse failed: %w", err)
	}

	return vmessJSONToClash(obj)
}

// vmessJSONToClash converts a V2RayN QRCode JSON (v=2 format) to a clash proxy map.
func vmessJSONToClash(obj map[string]any) (*node.ProxyNode, error) {
	name := jsonStr(obj, "ps")
	server := jsonStr(obj, "add")
	if server == "" {
		return nil, fmt.Errorf("vmess JSON missing 'add' field")
	}
	portRaw := obj["port"]
	port := 0
	switch v := portRaw.(type) {
	case float64:
		port = int(v)
	case string:
		port, _ = strconv.Atoi(v)
	}
	if port == 0 {
		return nil, fmt.Errorf("vmess JSON missing or zero 'port' field")
	}

	uuid := jsonStr(obj, "id")
	alterId := 0
	if aid, ok := obj["aid"]; ok {
		switch v := aid.(type) {
		case float64:
			alterId = int(v)
		case string:
			alterId, _ = strconv.Atoi(v)
		}
	}
	cipher := jsonStr(obj, "scy")
	if cipher == "" {
		cipher = "auto"
	}

	clash := map[string]any{
		"type":    "vmess",
		"name":    name,
		"server":  server,
		"port":    port,
		"uuid":    uuid,
		"alterId": alterId,
		"cipher":  cipher,
	}

	tlsStr := jsonStr(obj, "tls")
	if tlsStr == "tls" {
		clash["tls"] = true
	}
	if sni := jsonStr(obj, "sni"); sni != "" {
		clash["servername"] = sni
	}
	if fp := jsonStr(obj, "fp"); fp != "" {
		clash["client-fingerprint"] = fp
	}
	if alpnRaw := jsonStr(obj, "alpn"); alpnRaw != "" {
		clash["alpn"] = strings.Split(alpnRaw, ",")
	}

	net := jsonStr(obj, "net")
	host := jsonStr(obj, "host")
	path := jsonStr(obj, "path")
	switch net {
	case "ws":
		clash["network"] = "ws"
		wsOpts := map[string]any{}
		if path != "" {
			wsOpts["path"] = path
		}
		if host != "" {
			wsOpts["headers"] = map[string]any{"Host": host}
		}
		if len(wsOpts) > 0 {
			clash["ws-opts"] = wsOpts
		}
	case "grpc":
		clash["network"] = "grpc"
		if path != "" {
			clash["grpc-opts"] = map[string]any{"grpc-service-name": path}
		}
	case "h2", "http":
		clash["network"] = "h2"
		h2Opts := map[string]any{}
		if host != "" {
			h2Opts["host"] = []any{host}
		}
		if path != "" {
			h2Opts["path"] = path
		}
		if len(h2Opts) > 0 {
			clash["h2-opts"] = h2Opts
		}
	case "httpupgrade":
		clash["network"] = "ws"
		wsOpts := map[string]any{"v2ray-http-upgrade": true}
		if path != "" {
			wsOpts["path"] = path
		}
		if host != "" {
			wsOpts["headers"] = map[string]any{"Host": host}
		}
		clash["ws-opts"] = wsOpts
	}

	return node.New(clash)
}

// parseVMessURL parses the standard VMess URL format:
//
//	vmess://uuid@host:port?type=&security=&...#name
func parseVMessURL(link string) (*node.ProxyNode, error) {
	u, name, err := parseStdURL(link)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("vmess standard URL missing uuid in userinfo")
	}
	uuid := u.User.Username()
	server := u.Hostname()
	port := portFromStr(u.Port())
	if server == "" || port == 0 {
		return nil, fmt.Errorf("vmess standard URL missing server or port")
	}

	q := u.Query()
	clash := map[string]any{
		"type":    "vmess",
		"name":    name,
		"server":  server,
		"port":    port,
		"uuid":    uuid,
		"alterId": 0,
		"cipher":  "auto",
	}
	applyTLSTransportParams(clash, q, "servername")
	return node.New(clash)
}

// jsonStr safely extracts a string field from a JSON-decoded map.
func jsonStr(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}
