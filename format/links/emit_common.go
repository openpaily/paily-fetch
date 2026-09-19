package links

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ─── clash map helpers (duplicated from format/singbox for package isolation) ─

func lStr(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func lInt(m map[string]any, key string) int {
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

func lBool(m map[string]any, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	}
	return false
}

func lStringSlice(m map[string]any, key string) []string {
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
			if s, ok2 := item.(string); ok2 {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func lMap(m map[string]any, key string) map[string]any {
	v, ok := m[key]
	if !ok {
		return nil
	}
	sub, _ := v.(map[string]any)
	return sub
}

func lAnyString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case []any:
		if len(val) == 0 {
			return ""
		}
		s, _ := val[0].(string)
		return s
	case []string:
		if len(val) == 0 {
			return ""
		}
		return val[0]
	}
	return ""
}

// ─── URL construction helpers ─────────────────────────────────────────────────

// hostPort formats server:port, quoting IPv6 hosts.
func hostPort(server string, port int) string {
	if strings.ContainsRune(server, ':') {
		// IPv6
		return fmt.Sprintf("[%s]:%d", server, port)
	}
	return fmt.Sprintf("%s:%d", server, port)
}

// setTLSParams appends TLS-related query params to q.
// sniKey is the clash field for SNI ("servername" for vmess/vless, "sni" otherwise).
func setTLSParams(q url.Values, clash map[string]any, sniKey string) {
	if lBool(clash, "tls") {
		q.Set("security", "tls")
	}
	if sni := lStr(clash, sniKey); sni != "" {
		q.Set("sni", sni)
	}
	if fp := lStr(clash, "client-fingerprint"); fp != "" {
		q.Set("fp", fp)
	}
	if alpn := lStringSlice(clash, "alpn"); len(alpn) > 0 {
		q.Set("alpn", url.QueryEscape(strings.Join(alpn, ",")))
	}
	if lBool(clash, "skip-cert-verify") {
		q.Set("allowInsecure", "1")
	}
	if spx := lStr(clash, "spider-x"); spx != "" {
		q.Set("spx", spx)
	}
	if pqv := lStr(clash, "mldsa65-verify"); pqv != "" {
		q.Set("pqv", pqv)
	}
	if ech := lStr(clash, "ech"); ech != "" {
		q.Set("ech", ech)
	}
	if pcs := lStr(clash, "cert-sha"); pcs != "" {
		q.Set("pcs", pcs)
	}
	if fm := lStr(clash, "finalmask"); fm != "" {
		q.Set("fm", fm)
	}
	if ro := lMap(clash, "reality-opts"); ro != nil {
		q.Set("security", "reality")
		if pbk := lStr(ro, "public-key"); pbk != "" {
			q.Set("pbk", pbk)
		}
		if sid := lStr(ro, "short-id"); sid != "" {
			q.Set("sid", sid)
		}
	}
}

// setTransportParams appends network/transport query params to q.
func setTransportParams(q url.Values, clash map[string]any) {
	network := lStr(clash, "network")
	if network == "" {
		return
	}
	q.Set("type", network)

	switch network {
	case "ws":
		if wsOpts := lMap(clash, "ws-opts"); wsOpts != nil {
			if upgrade, _ := wsOpts["v2ray-http-upgrade"].(bool); upgrade {
				q.Set("type", "httpupgrade")
			}
			if path := lStr(wsOpts, "path"); path != "" {
				q.Set("path", path)
			}
			if hdrs := lMap(wsOpts, "headers"); hdrs != nil {
				if host, _ := hdrs["Host"].(string); host != "" {
					q.Set("host", host)
				}
			}
		}
	case "grpc":
		if grpcOpts := lMap(clash, "grpc-opts"); grpcOpts != nil {
			if svc := lStr(grpcOpts, "grpc-service-name"); svc != "" {
				q.Set("serviceName", svc)
			}
			if authority := lStr(grpcOpts, "grpc-authority"); authority != "" {
				q.Set("authority", authority)
			}
			if mode := lStr(grpcOpts, "grpc-mode"); mode != "" {
				q.Set("mode", mode)
			}
		}
	case "h2":
		if h2Opts := lMap(clash, "h2-opts"); h2Opts != nil {
			if path := lStr(h2Opts, "path"); path != "" {
				q.Set("path", path)
			}
			if hosts := lStringSlice(h2Opts, "host"); len(hosts) > 0 {
				q.Set("host", hosts[0])
			}
		}
	case "xhttp":
		if xhttpOpts := lMap(clash, "xhttp-opts"); xhttpOpts != nil {
			if path := lStr(xhttpOpts, "path"); path != "" {
				q.Set("path", path)
			}
			if host := lAnyString(xhttpOpts, "host"); host != "" {
				q.Set("host", host)
			}
			if mode := lStr(xhttpOpts, "mode"); mode != "" {
				q.Set("mode", mode)
			}
			if extra := lStr(xhttpOpts, "extra"); extra != "" {
				q.Set("extra", extra)
			}
		}
	case "kcp":
		if seed := lStr(clash, "seed"); seed != "" {
			q.Set("seed", seed)
		}
		if headerType := lStr(clash, "header-type"); headerType != "" {
			q.Set("headerType", headerType)
		}
	case "quic":
		if headerType := lStr(clash, "header-type"); headerType != "" {
			q.Set("headerType", headerType)
		}
		if quicSecurity := lStr(clash, "quic-security"); quicSecurity != "" {
			q.Set("quicSecurity", quicSecurity)
		}
		if key := lStr(clash, "key"); key != "" {
			q.Set("key", key)
		}
	case "tcp":
		if headerType := lStr(clash, "header-type"); headerType != "" {
			q.Set("headerType", headerType)
		}
		if host := lStr(clash, "host"); host != "" {
			q.Set("host", host)
		}
	}
}

// fragment returns the URL fragment encoding the node name.
func fragment(name string) string {
	return url.PathEscape(name)
}

// intToStr formats an int as decimal string or returns "" for 0.
func intToStr(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}
