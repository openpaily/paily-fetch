package format

import "sync"

var (
	mu       sync.RWMutex
	registry = map[string]FormatFactory{}
)

// Register adds a FormatFactory to the global registry.
// Panics if a factory with the same name is already registered.
func Register(f FormatFactory) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[f.Name()]; exists {
		panic("format: factory already registered: " + f.Name())
	}
	registry[f.Name()] = f
}

// Get returns the FormatFactory registered under name, or false if not found.
func Get(name string) (FormatFactory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := registry[name]
	return f, ok
}

// All returns a snapshot of all registered FormatFactory instances.
// The returned slice is unordered and independent of the registry's internal state.
func All() []FormatFactory {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]FormatFactory, 0, len(registry))
	for _, f := range registry {
		result = append(result, f)
	}
	return result
}
