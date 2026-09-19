package clash

import (
	"github.com/openpaily/paily-fetch/internal/format"
)

// Factory is the FormatFactory for the "clash" output format.
// It is registered via an init() function so that importing this package
// is sufficient to make the format available.
type Factory struct{}

var _ format.FormatFactory = (*Factory)(nil)

func init() {
	format.Register(&Factory{})
}

// Name returns the format identifier.
func (f *Factory) Name() string { return "clash" }

// NewGenerator creates a new, empty ClashGenerator for one generation request.
func (f *Factory) NewGenerator() format.FormatGenerator {
	return &Generator{}
}

// DefaultConfig returns nil because ClashGenerator ignores FormatConfig entirely.
func (f *Factory) DefaultConfig() format.FormatConfig { return format.FormatConfig(`{"template":""}`) }
