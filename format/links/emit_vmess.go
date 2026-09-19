package links

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// emitVMess generates a vmess:// link.
// v2rayn preference → base64(JSON v=2 format)
// subconverter preference → same (subconverter also parses base64 JSON)
func emitVMess(clash map[string]any, name, _ string) (string, bool) {
	server := lStr(clash, "server")
	port := lInt(clash, "port")
	uuid := lStr(clash, "uuid")
	if server == "" || port == 0 || uuid == "" {
		return "", false
	}

	obj := map[string]any{
		"v":    "2",
		"ps":   name,
		"add":  server,
		"port": port,
		"id":   uuid,
		"aid":  lInt(clash, "alterId"),
		"scy":  lStr(clash, "cipher"),
		"net":  lStr(clash, "network"),
	}
	if obj["net"] == "" {
		obj["net"] = "tcp"
	}
	if obj["scy"] == "" {
		obj["scy"] = "auto"
	}

	// TLS
	if lBool(clash, "tls") {
		obj["tls"] = "tls"
	} else {
		obj["tls"] = ""
	}
	if sni := lStr(clash, "servername"); sni != "" {
		obj["sni"] = sni
	}
	if fp := lStr(clash, "client-fingerprint"); fp != "" {
		obj["fp"] = fp
	}
	if lBool(clash, "skip-cert-verify") {
		obj["insecure"] = 1
	}
	if alpn := lStringSlice(clash, "alpn"); len(alpn) > 0 {
		obj["alpn"] = strings.Join(alpn, ",")
	}

	// Transport params
	network := lStr(clash, "network")
	switch network {
	case "ws":
		if wsOpts := lMap(clash, "ws-opts"); wsOpts != nil {
			if path := lStr(wsOpts, "path"); path != "" {
				obj["path"] = path
			}
			if hdrs := lMap(wsOpts, "headers"); hdrs != nil {
				if host, _ := hdrs["Host"].(string); host != "" {
					obj["host"] = host
				}
			}
		}
	case "grpc":
		if grpcOpts := lMap(clash, "grpc-opts"); grpcOpts != nil {
			obj["path"] = lStr(grpcOpts, "grpc-service-name")
		}
	case "h2":
		if h2Opts := lMap(clash, "h2-opts"); h2Opts != nil {
			if path := lStr(h2Opts, "path"); path != "" {
				obj["path"] = path
			}
			if hosts := lStringSlice(h2Opts, "host"); len(hosts) > 0 {
				obj["host"] = hosts[0]
			}
		}
	}

	// Reality opts
	if ro := lMap(clash, "reality-opts"); ro != nil {
		obj["tls"] = "reality"
		if pbk := lStr(ro, "public-key"); pbk != "" {
			obj["pbk"] = pbk
		}
		if sid := lStr(ro, "short-id"); sid != "" {
			obj["sid"] = sid
		}
	}

	j, err := json.Marshal(obj)
	if err != nil {
		return "", false
	}
	encoded := base64.StdEncoding.EncodeToString(j)
	return "vmess://" + encoded, true
}

// emitVLESS generates a vless:// link.
// It covers common VLESS fields but does not implement the complete RPRX link standard.
func emitVLESS(clash map[string]any, name string) (string, bool) {
	server := lStr(clash, "server")
	port := lInt(clash, "port")
	uuid := lStr(clash, "uuid")
	if server == "" || port == 0 || uuid == "" {
		return "", false
	}

	q := url.Values{}
	setTLSParams(q, clash, "servername")
	setTransportParams(q, clash)
	if flow := lStr(clash, "flow"); flow != "" {
		q.Set("flow", flow)
	}
	if pe := lStr(clash, "packet-encoding"); pe != "" {
		q.Set("packet-encoding", pe)
	}
	if enc := lStr(clash, "encryption"); enc != "" {
		q.Set("encryption", enc)
	} else {
		q.Set("encryption", "none")
	}

	link := fmt.Sprintf("vless://%s@%s?%s#%s",
		url.QueryEscape(uuid),
		hostPort(server, port),
		q.Encode(),
		fragment(name),
	)
	return link, true
}

// emitTrojan generates a trojan:// link.
func emitTrojan(clash map[string]any, name string) (string, bool) {
	server := lStr(clash, "server")
	port := lInt(clash, "port")
	password := lStr(clash, "password")
	if server == "" || port == 0 || password == "" {
		return "", false
	}

	q := url.Values{}
	setTLSParams(q, clash, "sni")
	setTransportParams(q, clash)
	if q.Get("security") == "" {
		q.Set("security", "tls")
	}

	link := fmt.Sprintf("trojan://%s@%s?%s#%s",
		url.QueryEscape(password),
		hostPort(server, port),
		q.Encode(),
		fragment(name),
	)
	return link, true
}
