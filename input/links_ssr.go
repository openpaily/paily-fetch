package input

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/openpaily/paily-fetch/node"
)

// parseSSR parses a ssr:// link.
// Format: ssr://base64(host:port:protocol:cipher:obfs:base64(password)/?obfsparam=base64&protoparam=base64&remarks=base64&group=base64)
func parseSSR(link string) (*node.ProxyNode, error) {
	raw := link[len("ssr://"):]

	decoded, err := base64Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("ssr base64 decode failed: %w", err)
	}

	// Split on '?' to separate main fields from query params
	mainPart := decoded
	queryPart := ""
	if idx := strings.IndexByte(decoded, '?'); idx >= 0 {
		mainPart = decoded[:idx]
		queryPart = decoded[idx+1:]
	}
	// Strip optional trailing '/' that some clients append before '?'
	mainPart = strings.TrimRight(mainPart, "/")

	// main: host:port:protocol:cipher:obfs:base64(password)
	parts := strings.SplitN(mainPart, ":", 6)
	if len(parts) != 6 {
		return nil, fmt.Errorf("ssr decoded string expected 6 colon-separated fields, got %d", len(parts))
	}

	server := parts[0]
	port := portFromStr(parts[1])
	protocol := parts[2]
	cipher := parts[3]
	obfs := parts[4]
	passB64 := parts[5]

	if server == "" || port == 0 {
		return nil, fmt.Errorf("ssr missing server or port")
	}

	password, err := base64Decode(passB64)
	if err != nil {
		return nil, fmt.Errorf("ssr password base64 decode failed: %w", err)
	}

	// Parse optional query params
	name := ""
	obfsParam := ""
	protoParam := ""
	if queryPart != "" {
		q, err := url.ParseQuery(queryPart)
		if err == nil {
			if r := q.Get("remarks"); r != "" {
				s, err := base64Decode(r)
				if err == nil {
					name = s
				}
			}
			if op := q.Get("obfsparam"); op != "" {
				s, err := base64Decode(op)
				if err == nil {
					obfsParam = s
				}
			}
			if pp := q.Get("protoparam"); pp != "" {
				s, err := base64Decode(pp)
				if err == nil {
					protoParam = s
				}
			}
		}
	}
	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	clash := map[string]any{
		"type":     "ssr",
		"name":     name,
		"server":   server,
		"port":     port,
		"cipher":   cipher,
		"password": password,
		"protocol": protocol,
		"obfs":     obfs,
	}
	if obfsParam != "" {
		clash["obfs-param"] = obfsParam
	}
	if protoParam != "" {
		clash["protocol-param"] = protoParam
	}

	return node.New(clash)
}
