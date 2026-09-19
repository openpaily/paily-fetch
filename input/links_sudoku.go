package input

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openpaily/paily-fetch/node"
)

// parseSudoku parses a sudoku:// link.
// Format: sudoku://base64url_nopad(json)
// where JSON: {"h","p","k","a","e","m","x","t","ts","hd","hm","ht","hh","hx","hy"}
func parseSudoku(link string) (*node.ProxyNode, error) {
	const prefix = "sudoku://"
	if !strings.HasPrefix(link, prefix) {
		return nil, fmt.Errorf("not a sudoku link")
	}
	encoded := link[len(prefix):]

	// Strip fragment (name)
	name := ""
	if idx := strings.IndexByte(encoded, '#'); idx >= 0 {
		name = encoded[idx+1:]
		encoded = encoded[:idx]
	}

	// Base64url without padding
	raw, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(encoded)
	if err != nil {
		// Try with padding normalised
		padded := encoded
		switch len(encoded) % 4 {
		case 2:
			padded += "=="
		case 3:
			padded += "="
		}
		raw, err = base64.URLEncoding.DecodeString(padded)
		if err != nil {
			return nil, fmt.Errorf("sudoku base64url decode failed: %w", err)
		}
	}

	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("sudoku JSON decode failed: %w", err)
	}

	server := jsonStr(obj, "h")
	if server == "" {
		return nil, fmt.Errorf("sudoku link missing host")
	}
	port := portFromStr(fmt.Sprintf("%v", obj["p"]))
	if port == 0 {
		// p might be a float64 from JSON
		if fv, ok := obj["p"].(float64); ok {
			port = int(fv)
		}
	}

	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	clash := map[string]any{
		"type":   "sudoku",
		"name":   name,
		"server": server,
		"port":   port,
	}

	setIfStr := func(clashKey, jsonKey string) {
		if v := jsonStr(obj, jsonKey); v != "" {
			clash[clashKey] = v
		}
	}

	setIfStr("key", "k")
	setIfStr("aead-method", "e")
	setIfStr("multiplexing", "m")

	// Table type: "ascii" → "prefer_ascii", "entropy" → "prefer_entropy"
	if a := jsonStr(obj, "a"); a != "" {
		switch a {
		case "ascii":
			clash["table-type"] = "prefer_ascii"
		case "entropy":
			clash["table-type"] = "prefer_entropy"
		default:
			clash["table-type"] = a
		}
	}

	// Padding min/max
	if t := jsonStr(obj, "t"); t != "" {
		clash["padding-min"] = t
	}
	if ts := jsonStr(obj, "ts"); ts != "" {
		clash["padding-max"] = ts
	}

	// enable-pure-downlink
	switch xv := obj["x"].(type) {
	case bool:
		if xv {
			clash["enable-pure-downlink"] = true
		}
	case string:
		if xv == "true" || xv == "1" {
			clash["enable-pure-downlink"] = true
		}
	case float64:
		if xv != 0 {
			clash["enable-pure-downlink"] = true
		}
	}

	// httpmask sub-object
	httpmask := map[string]any{}
	if hd := jsonStr(obj, "hd"); hd != "" {
		switch hd {
		case "true", "1":
			httpmask["disable"] = true
		}
	}
	if hm := jsonStr(obj, "hm"); hm != "" {
		httpmask["mode"] = hm
	}
	if ht := jsonStr(obj, "ht"); ht != "" {
		switch ht {
		case "true", "1":
			httpmask["tls"] = true
		}
	}
	if hh := jsonStr(obj, "hh"); hh != "" {
		httpmask["host"] = hh
	}
	if hx := jsonStr(obj, "hx"); hx != "" {
		// hx → multiplex
		switch hx {
		case "true", "1":
			httpmask["multiplex"] = true
		default:
			httpmask["multiplex"] = hx
		}
	}
	if hy := jsonStr(obj, "hy"); hy != "" {
		httpmask["path-root"] = hy
	}
	if len(httpmask) > 0 {
		clash["httpmask"] = httpmask
	}

	return node.New(clash)
}
