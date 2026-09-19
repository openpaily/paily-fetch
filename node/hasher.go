package node

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Hash returns a stable, content-based identifier for a proxy node.
//
// The hash encodes the tuple (type, server, port, auth-credential) where
// auth-credential is the primary secret field for the protocol:
//   - vmess / vless       → uuid
//   - trojan / anytls / hysteria / hysteria2 / tuic (password variant) → password
//   - tuic (uuid variant) → uuid
//   - ss / ssr            → password
//   - wireguard           → private-key
//   - socks5 / http       → username:password
//   - mieru               → username:password
//   - sudoku              → key
//   - snell               → psk
//   - (other)             → empty string
//
// The digest is the first 16 hex bytes of SHA-256(canonical) — 32 hex chars.
// If the clash map is missing "type", "server", or "port" the function returns
// an empty string (rather than panicking) so callers can treat it as unknown.
func Hash(clash map[string]any) string {
	ptype, _ := clash["type"].(string)
	server, _ := clash["server"].(string)
	port := clashPort(clash)
	if ptype == "" || server == "" || port == 0 {
		return ""
	}

	auth := authField(ptype, clash)
	canonical := fmt.Sprintf("%s|%s|%d|%s", ptype, server, port, auth)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:16]) // 32-char hex string
}

// authField returns the primary authentication credential for the given protocol.
func authField(ptype string, clash map[string]any) string {
	switch ptype {
	case "vmess", "vless":
		s, _ := clash["uuid"].(string)
		return s
	case "trojan", "anytls", "hysteria", "hysteria2":
		s, _ := clash["password"].(string)
		return s
	case "tuic":
		// TUIC V5 uses uuid; V4 uses only password
		if uuid, ok := clash["uuid"].(string); ok && uuid != "" {
			s, _ := clash["password"].(string)
			return uuid + ":" + s
		}
		s, _ := clash["password"].(string)
		return s
	case "ss", "ssr":
		s, _ := clash["password"].(string)
		return s
	case "wireguard":
		s, _ := clash["private-key"].(string)
		return s
	case "socks5", "http":
		user, _ := clash["username"].(string)
		pass, _ := clash["password"].(string)
		return user + ":" + pass
	case "mieru":
		user, _ := clash["username"].(string)
		pass, _ := clash["password"].(string)
		return user + ":" + pass
	case "sudoku":
		s, _ := clash["key"].(string)
		return s
	case "snell":
		s, _ := clash["psk"].(string)
		return s
	default:
		return ""
	}
}

// clashPort converts the "port" field (may be stored as int, float64, or numeric string).
func clashPort(clash map[string]any) int {
	switch v := clash["port"].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	default:
		return 0
	}
}
