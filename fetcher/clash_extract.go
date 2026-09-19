package fetcher

import "bytes"

// extractProxiesBlock scans raw Clash YAML bytes and extracts just the
// top-level "proxies:" block, avoiding parsing of dns, rules, proxy-groups
// and other heavy sections.
//
// Two complementary strategies handle both YAML value styles:
//
//  1. Indentation boundary (block style, the common case):
//     Any non-blank line at column 0 (after the "proxies:" header) signals a
//     new top-level key and terminates collection.
//
//  2. Bracket depth (flow style):
//     While bracket/brace depth is > 0 (an open '[' or '{' not yet closed),
//     every subsequent line is collected regardless of its indentation.  Once
//     depth returns to 0 the indentation rule resumes.
//
// Returns nil when the "proxies:" key is not found at column 0.
// The caller should fall back to full-document parsing when nil is returned
// or when the returned slice fails to unmarshal.
func extractProxiesBlock(data []byte) []byte {
	lines := bytes.Split(data, []byte("\n"))

	// Find "proxies:" as a top-level key (column 0).
	start := -1
	for i, line := range lines {
		if isTopLevelProxiesKey(trimCR(line)) {
			start = i
			break
		}
	}
	if start < 0 {
		return nil
	}

	var out bytes.Buffer
	if estimate := len(data) - start*32; estimate > 0 {
		out.Grow(estimate) // rough estimate
	}

	headerLine := trimCR(lines[start])
	out.Write(headerLine)
	out.WriteByte('\n')

	// Flow mode is only active when the header line itself opens a bracket
	// (e.g. "proxies: [" or "proxies: [{...").  In that case we collect
	// continuation lines regardless of indentation until the bracket closes.
	// For the common block-style "proxies:\n  - ..." the header delta is 0 and
	// we stay in indentation-only mode throughout, avoiding false triggers from
	// brackets inside individual proxy entry values.
	depth := bracketDelta(headerLine) // > 0 only for "proxies: [..."
	flowMode := depth > 0

	for i := start + 1; i < len(lines); i++ {
		bare := trimCR(lines[i])

		if flowMode {
			// Inside an open bracket from the header: collect until balanced.
			depth += bracketDelta(bare)
			if depth < 0 {
				depth = 0
			}
			out.Write(bare)
			out.WriteByte('\n')
			if depth == 0 {
				flowMode = false
			}
			continue
		}

		// Indentation-only mode (handles the common block-sequence case).
		// We deliberately do NOT track bracket depth here: brackets inside
		// individual proxy-entry values (unquoted regexes, IPv6, etc.) must
		// not affect the boundary detection.
		trimmed := bytes.TrimSpace(bare)
		if len(trimmed) == 0 {
			out.Write(bare)
			out.WriteByte('\n')
			continue
		}
		if bare[0] == ' ' || bare[0] == '\t' {
			out.Write(bare)
			out.WriteByte('\n')
			continue
		}
		// Zero-indentation block sequence entry ("- " or "-\n"): belongs to
		// the proxies list when the YAML spec allows the sequence indicator at
		// the same level as the mapping key.
		if bare[0] == '-' && (len(bare) == 1 || bare[1] == ' ' || bare[1] == '\t') {
			out.Write(bare)
			out.WriteByte('\n')
			continue
		}
		// Non-blank, zero-indentation, not a sequence entry: next top-level key — stop.
		break
	}

	b := out.Bytes()
	if len(b) == 0 {
		return nil
	}
	return b
}

// isTopLevelKey reports whether bare (CR-trimmed) is a top-level YAML key
// matching prefix exactly at column 0, followed by end-of-line, space, tab,
// or '#'. Works for any key: "proxies:", "dns:", "rules:", etc.
func isTopLevelKey(bare, prefix []byte) bool {
	if len(bare) == 0 || bare[0] == ' ' || bare[0] == '\t' {
		return false
	}
	if !bytes.HasPrefix(bare, prefix) {
		return false
	}
	rest := bare[len(prefix):]
	return len(rest) == 0 || rest[0] == ' ' || rest[0] == '\t' || rest[0] == '#'
}

// isTopLevelProxiesKey reports whether bare (CR-trimmed) is the top-level
// "proxies:" key in any of the common YAML scalar key forms:
//
//	proxies:      (unquoted plain scalar)
//	"proxies":    (double-quoted scalar)
//	'proxies':    (single-quoted scalar)
func isTopLevelProxiesKey(bare []byte) bool {
	return isTopLevelKey(bare, []byte("proxies:")) ||
		isTopLevelKey(bare, []byte(`"proxies":`)) ||
		isTopLevelKey(bare, []byte(`'proxies':`))
}

// bracketDelta returns the net change in bracket/brace depth for one YAML line,
// skipping content inside double-quoted and single-quoted strings and ignoring
// everything after an unquoted '#' (YAML comment).
func bracketDelta(line []byte) int {
	delta := 0
	inDouble := false
	inSingle := false
	for i := 0; i < len(line); i++ {
		b := line[i]
		switch {
		case inDouble:
			if b == '\\' {
				i++ // skip escaped character
			} else if b == '"' {
				inDouble = false
			}
		case inSingle:
			// YAML single-quote escape is '' (doubled apostrophe).
			if b == '\'' {
				if i+1 < len(line) && line[i+1] == '\'' {
					i++
				} else {
					inSingle = false
				}
			}
		default:
			switch b {
			case '"':
				inDouble = true
			case '\'':
				inSingle = true
			case '[', '{':
				delta++
			case ']', '}':
				delta--
			case '#':
				return delta // rest of line is a comment
			}
		}
	}
	return delta
}

// trimCR removes a trailing '\r' to normalise CRLF line endings.
func trimCR(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\r' {
		return b[:len(b)-1]
	}
	return b
}
