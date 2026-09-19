package links

import (
	"github.com/openpaily/paily-fetch/internal/format"
)

// Factory is the FormatFactory for the "links" output format.
type Factory struct{}

var _ format.FormatFactory = (*Factory)(nil)

func init() {
	format.Register(&Factory{})
}

// Name returns the format identifier.
func (f *Factory) Name() string { return "links" }

// NewGenerator creates a new, empty LinksGenerator for one generation request.
func (f *Factory) NewGenerator() format.FormatGenerator {
	return &Generator{}
}

// DefaultConfig returns the default preference config: v2rayn.
func (f *Factory) DefaultConfig() format.FormatConfig {
	return format.FormatConfig(`{"default":"v2rayn"}`)
}
