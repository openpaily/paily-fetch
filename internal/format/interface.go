package format

import "github.com/openpaily/paily-fetch/node"

// FormatConfig holds format-specific configuration as JSON bytes.
// nil means use the factory's DefaultConfig.
type FormatConfig []byte

// FormatGenerator builds a single output artifact from a collection of ProxyNodes.
// Implementations are not required to be safe for concurrent use.
type FormatGenerator interface {
	// Push adds a node to the generator's internal state.
	// name overrides the output name; if empty, n.Name() is used.
	// Protocols unsupported by this format are silently skipped with a log line.
	Push(n *node.ProxyNode, name string)

	// Generate serialises all pushed nodes into the output format.
	// config may be nil to use the factory's DefaultConfig.
	Generate(config FormatConfig) ([]byte, error)
}

// FormatFactory is a stateless descriptor for a single output format.
// Implementations must be safe for concurrent use.
type FormatFactory interface {
	// Name returns the unique identifier for this format (e.g. "clash", "singbox", "links").
	Name() string

	// NewGenerator creates a fresh, empty FormatGenerator.
	NewGenerator() FormatGenerator

	// DefaultConfig returns the default FormatConfig JSON for this format.
	// May return nil if the format has no configurable options.
	DefaultConfig() FormatConfig
}
