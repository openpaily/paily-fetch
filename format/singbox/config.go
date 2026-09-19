package singbox

import (
	"encoding/json"

	"github.com/openpaily/paily-fetch/internal/format"
)

// Config holds generation options for the sing-box output format.
// When Template is non-empty it must be a complete sing-box JSON configuration.
// The generator will:
//   - keep all management outbounds from the template (selector, urltest, direct,
//     dns, block, tproxy, redirect, tun, sniffer),
//   - discard any proxy outbounds already in the template (they are replaced),
//   - append every pushed proxy tag to the "outbounds" list of every selector and
//     urltest outbound, and
//   - assemble the final outbounds array as:
//     [selector/urltest outbounds] + [pushed proxy outbounds] + [direct/other infra].
//
// When Template is empty the generator emits a plain {"outbounds": [...]} document.
type Config struct {
	Template string `json:"template,omitempty"`
}

// parseConfig deserialises a FormatConfig JSON blob into a Config.
// A nil or empty blob returns a zero-value Config (no template).
func parseConfig(raw format.FormatConfig) Config {
	if len(raw) == 0 {
		return Config{}
	}
	var c Config
	_ = json.Unmarshal(raw, &c)
	return c
}

// managementTypes are sing-box outbound types that represent routing/management
// constructs. These are preserved from the template; everything else is replaced
// by the pushed proxy outbounds.
var managementTypes = map[string]bool{
	"selector": true,
	"urltest":  true,
	"direct":   true,
	"dns":      true,
	"block":    true,
	"tproxy":   true,
	"redirect": true,
	"tun":      true,
	"sniffer":  true,
}
