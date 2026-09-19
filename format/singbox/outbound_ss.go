package singbox

import (
	"fmt"
	"strings"
)

// toSingboxSS converts a clash Shadowsocks proxy map to a sing-box shadowsocks outbound.
// The caller has already filtered out non-standard plugins (shadow-tls, restls, etc.).
func toSingboxSS(clash map[string]any, tag string) map[string]any {
	ob := map[string]any{
		"type":        "shadowsocks",
		"tag":         tag,
		"server":      clashStr(clash, "server"),
		"server_port": clashInt(clash, "port"),
		"method":      clashStr(clash, "cipher"),
		"password":    clashStr(clash, "password"),
	}

	plugin := clashStr(clash, "plugin")
	if plugin == "" {
		return ob
	}

	// Map clash plugin name to sing-box plugin name
	sbPlugin := plugin
	if plugin == "obfs" {
		sbPlugin = "obfs-local"
	}
	ob["plugin"] = sbPlugin

	// Build plugin_opts string from clash plugin-opts map
	if opts := clashMap(clash, "plugin-opts"); opts != nil {
		ob["plugin_opts"] = ssPluginOptsString(plugin, opts)
	}

	return ob
}

// ssPluginOptsString converts clash plugin-opts map to the option string expected by sing-box.
func ssPluginOptsString(plugin string, opts map[string]any) string {
	switch plugin {
	case "obfs", "obfs-local":
		// "obfs=http;obfs-host=www.example.com"
		parts := []string{}
		if mode := clashStr(opts, "mode"); mode != "" {
			parts = append(parts, "obfs="+mode)
		}
		if host := clashStr(opts, "host"); host != "" {
			parts = append(parts, "obfs-host="+host)
		}
		return strings.Join(parts, ";")

	case "v2ray-plugin":
		// "mode=websocket;host=...;path=...;tls;mux=..."
		parts := []string{}
		if mode := clashStr(opts, "mode"); mode != "" {
			parts = append(parts, "mode="+mode)
		}
		if host := clashStr(opts, "host"); host != "" {
			parts = append(parts, "host="+host)
		}
		if path := clashStr(opts, "path"); path != "" {
			parts = append(parts, "path="+path)
		}
		if clashBool(opts, "tls") {
			parts = append(parts, "tls")
		}
		if mux := clashBool(opts, "mux"); mux {
			parts = append(parts, "mux=8")
		}
		return strings.Join(parts, ";")

	default:
		// Fallback: key=value pairs
		parts := []string{}
		for k, v := range opts {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
		return strings.Join(parts, ";")
	}
}
