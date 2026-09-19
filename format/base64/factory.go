// Package base64fmt registers the base64-encoded share-link list format under the
// name "base64".  It behaves identically to format/links but the output is the
// standard base64 encoding (RFC 4648) of the newline-separated link list.
package base64fmt

import (
	b64 "encoding/base64"
	"fmt"

	"github.com/openpaily/paily-fetch/format/links"
	iformat "github.com/openpaily/paily-fetch/internal/format"
	"github.com/openpaily/paily-fetch/node"
)

// factory is the FormatFactory for the "base64" output format.
type factory struct{}

var _ iformat.FormatFactory = (*factory)(nil)

func (f *factory) Name() string { return "base64" }

func (f *factory) NewGenerator() iformat.FormatGenerator {
	return &generator{inner: &links.Generator{}}
}

func (f *factory) DefaultConfig() iformat.FormatConfig {
	return iformat.FormatConfig(`{"default":"v2rayn"}`)
}

func init() {
	iformat.Register(&factory{})
}

// generator wraps links.Generator and base64-encodes its output.
type generator struct {
	inner *links.Generator
}

var _ iformat.FormatGenerator = (*generator)(nil)

func (g *generator) Push(n *node.ProxyNode, name string) {
	g.inner.Push(n, name)
}

func (g *generator) Generate(cfg iformat.FormatConfig) ([]byte, error) {
	plain, err := g.inner.Generate(cfg)
	if err != nil {
		return nil, fmt.Errorf("base64 generator: %w", err)
	}
	encoded := b64.StdEncoding.EncodeToString(plain)
	return []byte(encoded), nil
}
