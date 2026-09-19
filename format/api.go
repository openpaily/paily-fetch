// Package format exposes the FormatFactory / FormatGenerator interface pair and
// the global format registry as a public API so that external modules can
// register and look up output formats.
//
// The concrete implementations live in sub-packages:
//
//	format/clash   – Clash/Mihomo YAML
//	format/singbox – sing-box JSON
//	format/links   – share-link URI list (registered as "links")
//	format/base64  – share-link URI list, base64-encoded (registered as "base64")
package format

import iformat "github.com/openpaily/paily-fetch/internal/format"

// FormatConfig is the opaque per-format configuration blob (JSON bytes).
type FormatConfig = iformat.FormatConfig

// FormatGenerator is a single-use, stateful generator for one distribution request.
type FormatGenerator = iformat.FormatGenerator

// FormatFactory is the stateless per-format factory registered once at startup.
type FormatFactory = iformat.FormatFactory

// Register adds a factory to the global registry.
// Panics if a factory with the same name has already been registered.
func Register(f FormatFactory) { iformat.Register(f) }

// Get returns the FormatFactory registered under name, or (nil, false) if not found.
func Get(name string) (FormatFactory, bool) { return iformat.Get(name) }

// All returns a snapshot of all registered FormatFactory instances.
func All() []FormatFactory { return iformat.All() }
