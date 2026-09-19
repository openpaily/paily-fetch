package links

import (
	"fmt"
	"net/url"
	"strings"
)

// emitHysteria generates a hysteria:// link (Hysteria V1).
func emitHysteria(clash map[string]any, name string) (string, bool) {
	server := lStr(clash, "server")
	port := lInt(clash, "port")
	if server == "" || port == 0 {
		return "", false
	}

	q := url.Values{}
	if authStr := lStr(clash, "auth-str"); authStr != "" {
		q.Set("auth_str", authStr)
	}
	if up := lStr(clash, "up"); up != "" {
		// Strip " Mbps" suffix to get the bare number
		q.Set("upmbps", trimMbps(up))
	}
	if down := lStr(clash, "down"); down != "" {
		q.Set("downmbps", trimMbps(down))
	}
	if sni := lStr(clash, "sni"); sni != "" {
		q.Set("peer", sni)
	}
	if lBool(clash, "skip-cert-verify") {
		q.Set("insecure", "1")
	}
	if obfs := lStr(clash, "obfs"); obfs != "" {
		q.Set("obfsParam", obfs)
	}
	if alpn := lStringSlice(clash, "alpn"); len(alpn) > 0 {
		q.Set("alpn", strings.Join(alpn, ","))
	}
	if protocol := lStr(clash, "protocol"); protocol != "" && protocol != "udp" {
		q.Set("protocol", protocol)
	}
	if ports := lStr(clash, "ports"); ports != "" {
		q.Set("ports", ports)
	}

	link := fmt.Sprintf("hysteria://%s?%s#%s",
		hostPort(server, port),
		q.Encode(),
		fragment(name),
	)
	return link, true
}

// emitHysteria2 generates a hy2:// link.
// v2rayn preference → uses mport= param; subconverter preference → uses ports= param.
func emitHysteria2(clash map[string]any, name, pref string) (string, bool) {
	server := lStr(clash, "server")
	port := lInt(clash, "port")
	password := lStr(clash, "password")
	if server == "" || port == 0 {
		return "", false
	}

	q := url.Values{}
	if sni := lStr(clash, "sni"); sni != "" {
		q.Set("sni", sni)
	}
	if lBool(clash, "skip-cert-verify") {
		q.Set("insecure", "1")
	}
	if obfs := lStr(clash, "obfs"); obfs != "" {
		q.Set("obfs", obfs)
	}
	if obfsPass := lStr(clash, "obfs-password"); obfsPass != "" {
		q.Set("obfs-password", obfsPass)
	}
	if up := lStr(clash, "up"); up != "" {
		q.Set("up", trimMbps(up))
	}
	if down := lStr(clash, "down"); down != "" {
		q.Set("down", trimMbps(down))
	}
	if ports := lStr(clash, "ports"); ports != "" {
		if pref == prefSubconverter {
			q.Set("ports", ports)
		} else {
			q.Set("mport", ports) // v2rayN uses mport
		}
	}

	userinfo := url.QueryEscape(password)
	link := fmt.Sprintf("hy2://%s@%s?%s#%s",
		userinfo,
		hostPort(server, port),
		q.Encode(),
		fragment(name),
	)
	return link, true
}

// emitTUIC generates a tuic:// link (V5 only).
func emitTUIC(clash map[string]any, name string) (string, bool) {
	server := lStr(clash, "server")
	port := lInt(clash, "port")
	uuid := lStr(clash, "uuid")
	password := lStr(clash, "password")
	if server == "" || port == 0 || uuid == "" {
		return "", false
	}

	q := url.Values{}
	if sni := lStr(clash, "sni"); sni != "" {
		q.Set("sni", sni)
	}
	if lBool(clash, "skip-cert-verify") {
		q.Set("insecure", "1")
	}
	if alpn := lStringSlice(clash, "alpn"); len(alpn) > 0 {
		q.Set("alpn", strings.Join(alpn, ","))
	}
	if cc := lStr(clash, "congestion-controller"); cc != "" {
		q.Set("congestion_control", cc)
	}
	if udpMode := lStr(clash, "udp-relay-mode"); udpMode != "" {
		q.Set("udp_relay_mode", udpMode)
	}

	// uuid:password in userinfo
	userinfo := url.QueryEscape(uuid) + ":" + url.QueryEscape(password)
	link := fmt.Sprintf("tuic://%s@%s?%s#%s",
		userinfo,
		hostPort(server, port),
		q.Encode(),
		fragment(name),
	)
	return link, true
}

// emitWireGuard generates a wg:// link.
func emitWireGuard(clash map[string]any, name string) (string, bool) {
	server := lStr(clash, "server")
	port := lInt(clash, "port")
	privateKey := lStr(clash, "private-key")
	publicKey := lStr(clash, "public-key")
	if server == "" || port == 0 || privateKey == "" || publicKey == "" {
		return "", false
	}

	q := url.Values{}
	q.Set("publickey", publicKey)

	// address (ip/ipv6)
	addresses := []string{}
	if ip := lStr(clash, "ip"); ip != "" {
		addresses = append(addresses, ip)
	}
	if ipv6 := lStr(clash, "ipv6"); ipv6 != "" {
		addresses = append(addresses, ipv6)
	}
	if len(addresses) > 0 {
		q.Set("address", strings.Join(addresses, ","))
	}

	if mtu := lInt(clash, "mtu"); mtu > 0 {
		q.Set("mtu", fmt.Sprintf("%d", mtu))
	}

	// reserved: []uint8 or []any or string
	if rv := clash["reserved"]; rv != nil {
		switch v := rv.(type) {
		case []uint8:
			parts := make([]string, len(v))
			for i, b := range v {
				parts[i] = fmt.Sprintf("%d", b)
			}
			q.Set("reserved", strings.Join(parts, ","))
		case []any:
			parts := make([]string, 0, len(v))
			for _, item := range v {
				parts = append(parts, fmt.Sprintf("%v", item))
			}
			q.Set("reserved", strings.Join(parts, ","))
		case string:
			if v != "" {
				q.Set("reserved", v)
			}
		}
	}

	link := fmt.Sprintf("wg://%s@%s?%s#%s",
		url.QueryEscape(privateKey),
		hostPort(server, port),
		q.Encode(),
		fragment(name),
	)
	return link, true
}

// trimMbps strips " Mbps" or "Mbps" suffix from a bandwidth string.
func trimMbps(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(strings.ToLower(s), " mbps")
	s = strings.TrimSuffix(s, "mbps")
	return strings.TrimSpace(s)
}
