package links

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// emitSudoku generates a sudoku:// link.
// Format: sudoku://base64url_nopad(json)
//
// JSON field mapping (clash → sudoku link):
//   server → h
//   port → p
//   key → k
//   table-type ("prefer_ascii"→"ascii", "prefer_entropy"→"entropy") → a
//   aead-method → e
//   multiplexing → m
//   enable-pure-downlink → x
//   httpmask.disable → hd
//   httpmask.mode → hm
//   httpmask.tls → ht
//   httpmask.host → hh
//   httpmask.multiplex → hx
//   httpmask.path-root → hy
func emitSudoku(clash map[string]any, name string) (string, bool) {
	server := lStr(clash, "server")
	port := lInt(clash, "port")
	key := lStr(clash, "key")
	if server == "" || port == 0 || key == "" {
		return "", false
	}

	obj := map[string]any{
		"h": server,
		"p": port,
		"k": key,
	}

	if tt := lStr(clash, "table-type"); tt != "" {
		switch tt {
		case "prefer_ascii":
			obj["a"] = "ascii"
		case "prefer_entropy":
			obj["a"] = "entropy"
		default:
			obj["a"] = tt
		}
	}
	if ae := lStr(clash, "aead-method"); ae != "" {
		obj["e"] = ae
	}
	if mux := lStr(clash, "multiplexing"); mux != "" {
		obj["m"] = mux
	}
	if lBool(clash, "enable-pure-downlink") {
		obj["x"] = true
	}

	if hm := lMap(clash, "httpmask"); hm != nil {
		if lBool(hm, "disable") {
			obj["hd"] = true
		}
		if mode := lStr(hm, "mode"); mode != "" {
			obj["hm"] = mode
		}
		if lBool(hm, "tls") {
			obj["ht"] = true
		}
		if host := lStr(hm, "host"); host != "" {
			obj["hh"] = host
		}
		if mx, ok := hm["multiplex"]; ok {
			switch v := mx.(type) {
			case bool:
				if v {
					obj["hx"] = "on"
				} else {
					obj["hx"] = "off"
				}
			case string:
				if v != "" {
					obj["hx"] = v
				}
			}
		}
		if pr := lStr(hm, "path-root"); pr != "" {
			obj["hy"] = pr
		}
	}

	j, err := json.Marshal(obj)
	if err != nil {
		return "", false
	}

	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(j)

	// name appended as fragment if non-empty and different from host:port default
	frag := ""
	defaultName := fmt.Sprintf("%s:%d", server, port)
	if name != "" && name != defaultName {
		frag = "#" + fragment(name)
	}

	return "sudoku://" + encoded + frag, true
}

// _ suppresses unused import warning for strings
var _ = strings.TrimSpace
