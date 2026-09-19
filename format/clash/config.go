package clash

import (
	"encoding/json"

	"github.com/openpaily/paily-fetch/internal/format"
)

// Config holds generation options for the clash output format.
// When Template is non-empty it must be a complete Clash YAML configuration.
// The generator will:
//   - replace the top-level "proxies" list with all pushed proxy nodes, and
//   - append every pushed node's name to the "proxies" list of every proxy-group.
//
// When Template is empty the generator emits a plain {"proxies": [...]} document.
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
