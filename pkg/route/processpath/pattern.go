package processpath

import (
	"fmt"
	"strings"
	"unicode/utf8"
	"unsafe"
)

// Kind classifies a process list entry.
type Kind uint8

const (
	// KindExact is a path or name without wildcards, matched by equality.
	KindExact Kind = iota
	// KindGlob is a pattern with *, ? or **.
	KindGlob
	// KindForeign is a valid path or pattern of the other platform family
	// (a Windows path on Unix, or a Unix path on Windows). Shared lists may
	// carry entries for several platforms; these never match on this host.
	KindForeign
)

// PatternError explains why an entry cannot be used.
type PatternError struct {
	Pattern string
	Reason  string
}

func (e *PatternError) Error() string {
	return fmt.Sprintf("invalid process pattern %q: %s", e.Pattern, e.Reason)
}

type segKind uint8

const (
	segLiteral segKind = iota
	segWild            // * and ? inside one component
	segAny             // ** : zero or more components
)

type segment struct {
	kind segKind
	text string
}

func (s segment) match(component string) bool {
	switch s.kind {
	case segLiteral:
		return s.text == component
	case segWild:
		return wildMatch(s.text, component)
	}
	return false
}

// Pattern is a compiled process list entry.
type Pattern struct {
	kind Kind
	// key identifies equal patterns: the canonical path of an exact entry, or
	// a unique encoding of a glob pattern.
	key      string
	floating bool   // starts with **: any root
	root     string // canonical root of an anchored glob
	segs     []segment
}

// Kind reports how the entry is matched.
func (p Pattern) Kind() Kind { return p.kind }

func hasWildcard(s string) bool { return strings.ContainsAny(s, "*?") }

// Compile parses and validates one process list entry for flavor f.
//
// Accepted forms:
//
//	/usr/bin/curl, C:\Windows\a.exe   absolute path: exact match
//	com.example.app, :System         name without separators: exact match
//	/opt/app/**                      absolute glob
//	**/aaa/**                        glob matching under any root
//
// * and ? match within one component; ** must be a whole component and
// matches zero or more components, except at the end where it matches one
// or more so that "dir/**" covers the files below dir but not dir itself.
func (f Flavor) Compile(entry string) (Pattern, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return Pattern{}, &PatternError{entry, "empty entry"}
	}
	invalid := func(reason string, args ...any) (Pattern, error) {
		return Pattern{}, &PatternError{entry, fmt.Sprintf(reason, args...)}
	}
	if other, ok := f.foreignFlavor(entry); ok {
		if _, err := other.Compile(entry); err != nil {
			return Pattern{}, err
		}
		return Pattern{kind: KindForeign, key: entry}, nil
	}
	if f.deleted {
		entry = strings.TrimSuffix(entry, " (deleted)")
	}

	floating := false
	var root, rest string
	firstComponent, _ := splitFirst(entry, f.isSep)
	switch {
	case firstComponent == "**":
		floating, rest = true, entry
	case f.windows:
		parsed, tail, ok := f.windowsRoot(entry)
		if !ok {
			switch {
			case len(entry) >= 2 && entry[1] == ':' && (entry[0] == '*' || entry[0] == '?'):
				return invalid("wildcard drive letters are not supported; start the pattern with **/ to match any drive")
			case len(entry) >= 2 && isLetter(entry[0]) && entry[1] == ':':
				return invalid("drive-relative paths are not supported; write %c:\\...", entry[0])
			case f.isSep(entry[0]):
				return invalid("the path has no drive letter; write C:\\... for one drive or **/... for any drive")
			}
			return f.compileName(entry)
		}
		if hasWildcard(parsed.a) || hasWildcard(parsed.b) {
			return invalid("wildcards are not supported in the drive, server, share or device name; start the pattern with **/ instead")
		}
		root, rest = string(parsed.appendTo(nil)), tail
	case entry[0] == '/':
		rest = entry
	default:
		return f.compileName(entry)
	}

	segs := make([]segment, 0, 8)
	for component := range strings.FieldsFuncSeq(rest, func(r rune) bool { return r < utf8.RuneSelf && f.isSep(byte(r)) }) {
		switch {
		case component == ".":
			continue
		case component == "..":
			if len(segs) == 0 {
				return invalid("\"..\" climbs above the root")
			}
			if segs[len(segs)-1].kind != segLiteral {
				return invalid("\"..\" cannot follow a wildcard component")
			}
			segs = segs[:len(segs)-1]
			continue
		case component == "**":
			if len(segs) == 0 || segs[len(segs)-1].kind != segAny {
				segs = append(segs, segment{kind: segAny})
			}
			continue
		case strings.Contains(component, "**"):
			return invalid("** must be a whole path component, as in /dir/**/name; use * inside a component")
		}
		text := component
		if f.windows {
			text = string(appendFold(nil, component))
		}
		kind := segLiteral
		if hasWildcard(text) {
			kind = segWild
		}
		segs = append(segs, segment{kind: kind, text: text})
	}

	glob := floating
	for _, seg := range segs {
		glob = glob || seg.kind != segLiteral
	}
	if !glob {
		var buf strings.Builder
		buf.WriteString(root)
		for _, seg := range segs {
			buf.WriteByte('/')
			buf.WriteString(seg.text)
		}
		if len(segs) == 0 {
			buf.WriteByte('/')
		}
		return Pattern{kind: KindExact, key: buf.String()}, nil
	}
	// A trailing ** means "below this directory": at least one component.
	if segs[len(segs)-1].kind == segAny {
		segs = append(segs[:len(segs)-1], segment{kind: segWild, text: "*"}, segment{kind: segAny})
	}
	p := Pattern{kind: KindGlob, floating: floating, root: root, segs: segs}
	var key strings.Builder
	if floating {
		key.WriteString("F")
	} else {
		key.WriteString("A")
		key.WriteString(root)
	}
	for _, seg := range segs {
		key.WriteByte(0)
		key.WriteByte(byte('0' + seg.kind))
		key.WriteString(seg.text)
	}
	p.key = key.String()
	return p, nil
}

// compileName accepts a bare name such as an Android package or a Windows
// pseudo process (":System"), compared exactly as reported.
func (f Flavor) compileName(entry string) (Pattern, error) {
	for component := range strings.FieldsFuncSeq(entry, func(r rune) bool { return r == '/' || r == '\\' }) {
		if component != "**" && strings.Contains(component, "**") {
			return Pattern{}, &PatternError{entry, "** must be a whole path component, as in **/name/**; use * inside a component"}
		}
	}
	if hasWildcard(entry) {
		return Pattern{}, &PatternError{entry, "a pattern must be an absolute path or start with **/"}
	}
	for i := 0; i < len(entry); i++ {
		if entry[i] == '/' || f.isSep(entry[i]) {
			return Pattern{}, &PatternError{entry, "relative paths never match; use an absolute path or start with **/"}
		}
	}
	return Pattern{kind: KindExact, key: entry}, nil
}

// foreignFlavor recognizes absolute paths of the other platform family.
func (f Flavor) foreignFlavor(entry string) (Flavor, bool) {
	if f.windows {
		// A single leading "/" is a Unix path; Windows would read it as
		// relative to the current drive. "//" stays a UNC path.
		if entry[0] == '/' && (len(entry) == 1 || entry[1] != '/') {
			return Unix, true
		}
		return Flavor{}, false
	}
	if _, _, ok := Windows.windowsRoot(entry); ok && !strings.HasPrefix(entry, "/") {
		return Windows, true
	}
	if len(entry) >= 2 && isLetter(entry[0]) && entry[1] == ':' || strings.HasPrefix(entry, `\`) {
		// C:foo, \foo: let the Windows rules explain the problem.
		return Windows, true
	}
	return Flavor{}, false
}

// wildMatch matches name against a component pattern with * and ?; ? is one
// rune.
func wildMatch(pattern, name string) bool {
	p, n := 0, 0
	star, mark := -1, 0
	for n < len(name) {
		if p < len(pattern) {
			switch c := pattern[p]; c {
			case '*':
				star, mark = p, n
				p++
				continue
			case '?':
				_, size := utf8.DecodeRuneInString(name[n:])
				p++
				n += size
				continue
			default:
				if c == name[n] {
					p++
					n++
					continue
				}
			}
		}
		if star < 0 {
			return false
		}
		p = star + 1
		_, size := utf8.DecodeRuneInString(name[mark:])
		mark += size
		n = mark
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// matchSegments matches components against segments; segAny matches any
// number of components and every other segment exactly one.
func matchSegments(segs []segment, components components) bool {
	s, c := 0, 0
	star, mark := -1, 0
	for c < len(components.spans) {
		if s < len(segs) {
			if segs[s].kind == segAny {
				star, mark = s, c
				s++
				continue
			}
			if segs[s].match(components.at(c)) {
				s++
				c++
				continue
			}
		}
		if star < 0 {
			return false
		}
		s = star + 1
		mark++
		c = mark
	}
	for s < len(segs) && segs[s].kind == segAny {
		s++
	}
	return s == len(segs)
}

func bytesString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}
