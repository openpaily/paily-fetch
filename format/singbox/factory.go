package singbox

import (
	"github.com/openpaily/paily-fetch/internal/format"
)

// Factory is the FormatFactory for the "singbox" output format.
type Factory struct{}

var _ format.FormatFactory = (*Factory)(nil)

func init() {
	format.Register(&Factory{})
}

// Name returns the format identifier.
func (f *Factory) Name() string { return "singbox" }

// NewGenerator creates a new, empty SingboxGenerator for one generation request.
func (f *Factory) NewGenerator() format.FormatGenerator {
	return &Generator{items: []map[string]any{}}
}

// DefaultConfig returns an empty JSON object since SingboxGenerator ignores config.
func (f *Factory) DefaultConfig() format.FormatConfig { return format.FormatConfig(`{"template":""}`) }
