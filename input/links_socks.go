package input

import (
	"fmt"

	"github.com/openpaily/paily-fetch/node"
)

// parseSOCKS parses socks5:// or socks:// links.
// Supports both:
//   - Standard: socks5://[user:pass@]host:port#name
//   - v2rayN base64: socks://base64(user:pass@host:port)#name
func parseSOCKS(link string) (*node.ProxyNode, error) {
	// Extract raw after scheme
	rawAfter := ""
	scheme := ""
	switch {
	case len(link) > 9 && link[:9] == "socks5://":
		rawAfter = link[9:]
		scheme = "socks5"
	case len(link) > 8 && link[:8] == "socks://":
		rawAfter = link[8:]
		scheme = "socks"
	default:
		return nil, fmt.Errorf("unrecognised socks scheme")
	}

	// Extract name from fragment
	name := ""
	raw := rawAfter
	if idx := indexByteAfterPath(raw, '#'); idx >= 0 {
		fragEncoded := raw[idx+1:]
		if decoded, err := urlQueryUnescape(fragEncoded); err == nil {
			name = decoded
		} else {
			name = fragEncoded
		}
		raw = raw[:idx]
	}

	// Detect v2rayN-style socks:// with base64 userinfo (no '@' in the base64 block)
	// The heuristic: if scheme is "socks" and there's no '@' visible, try base64 decode.
	if scheme == "socks" {
		if idx := indexByteAfterPath(raw, '@'); idx < 0 {
			// Try base64 decode
			decoded, err := base64Decode(raw)
			if err == nil {
				raw = decoded
			}
		}
	}

	// Now raw should be [user:pass@]host:port
	u, _, err := parseStdURL("socks5://" + raw + "#" + name)
	if err != nil {
		return nil, fmt.Errorf("socks URL parse failed: %w", err)
	}

	server := u.Hostname()
	port := portFromStr(u.Port())
	if server == "" || port == 0 {
		return nil, fmt.Errorf("socks URL missing server or port")
	}
	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	clash := map[string]any{
		"type":   "socks5",
		"name":   name,
		"server": server,
		"port":   port,
	}
	if u.User != nil {
		if user := u.User.Username(); user != "" {
			clash["username"] = user
		}
		if pass, ok := u.User.Password(); ok && pass != "" {
			clash["password"] = pass
		}
	}

	return node.New(clash)
}

// indexByteAfterPath returns the index of b in s, or -1 if not found.
// (thin wrapper around strings.IndexByte for clarity)
func indexByteAfterPath(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// urlQueryUnescape wraps net/url.QueryUnescape to avoid importing net/url in this file.
func urlQueryUnescape(s string) (string, error) {
	return unescapeURL(s)
}
