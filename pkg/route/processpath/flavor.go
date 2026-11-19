// Package processpath normalizes executable paths and matches them against
// process list entries: exact paths and glob patterns with *, ? and **.
//
// Matching is shared by every platform; only path syntax differs. A Flavor
// describes one platform's syntax and can be chosen explicitly, so Windows
// and macOS behaviour is testable on any host.
//
// Canonical form. A normalized absolute path is its root followed by "/" and
// its components joined by "/":
//
//	Unix               /usr/bin/curl                 -> /usr/bin/curl
//	Windows drive      C:\Program Files\A\a.exe      -> C:/PROGRAM FILES/A/A.EXE
//	Windows UNC        \\server\share\A\a.exe        -> //SERVER/SHARE/A/A.EXE
//	NT device (known)  \Device\HarddiskVolume3\a.exe -> C:/A.EXE
//	NT device (other)  \Device\HarddiskVolume9\a.exe -> //?/DEVICE/HARDDISKVOLUME9/A.EXE
//
// The root (drive, UNC server and share, or device) is not a path component:
// only a pattern starting with **/ matches across roots.
package processpath

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Flavor is the path syntax of one platform.
type Flavor struct {
	windows bool
	// deleted strips the " (deleted)" marker Linux appends to /proc/PID/exe
	// when the executable was unlinked while running.
	deleted bool
	// devices maps folded NT device names (\DEVICE\HARDDISKVOLUME3) to the
	// folded drive root that currently mounts them (C:).
	devices map[string]string
}

var (
	// Linux paths are case-sensitive and may carry a " (deleted)" suffix.
	Linux = Flavor{deleted: true}
	// Darwin paths are compared case-sensitively. APFS and HFS+ volumes are
	// usually case-insensitive but not always, and the kernel reports the
	// on-disk spelling, so folding would only risk false matches.
	Darwin = Flavor{}
	// Unix is any other Unix-like system.
	Unix = Flavor{}
	// Windows paths are case-insensitive and accept both separators.
	Windows = Flavor{windows: true}
)

// WithDevices returns f with an NT device to drive letter table, for example
// {`\Device\HarddiskVolume3`: `C:`}. Unknown devices stay distinct roots.
func (f Flavor) WithDevices(devices map[string]string) Flavor {
	if !f.windows || len(devices) == 0 {
		f.devices = nil
		return f
	}
	f.devices = make(map[string]string, len(devices))
	for device, drive := range devices {
		device = strings.TrimRight(strings.ReplaceAll(device, "/", `\`), `\`)
		drive = strings.TrimRight(drive, `\/`)
		if len(drive) != 2 || drive[1] != ':' || !isLetter(drive[0]) {
			continue
		}
		f.devices[string(appendFold(nil, device))] = string(appendFold(nil, drive))
	}
	return f
}

// Normalize returns the canonical form of an absolute path. A path that is
// not absolute for f is returned unchanged with ok false; it can only be
// matched exactly.
func (f Flavor) Normalize(path string) (canonical string, ok bool) {
	var buf [256]byte
	p, ok := f.normalize(buf[:0], path)
	if !ok {
		return path, false
	}
	return strings.Clone(p.s), true
}

// normalized is a canonical path. s may alias the input or a caller buffer.
type normalized struct {
	s    string
	root int // s[:root] is the root; components start at s[root+1:]
}

func (n normalized) rootString() string { return n.s[:n.root] }
func (n normalized) rest() string {
	if n.root+1 >= len(n.s) {
		return ""
	}
	return n.s[n.root+1:]
}

func (f Flavor) isSep(c byte) bool { return c == '/' || f.windows && c == '\\' }

// normalize writes the canonical form of path into buf when it differs from
// path. The result is valid only while buf and path are.
func (f Flavor) normalize(buf []byte, path string) (normalized, bool) {
	if f.windows {
		root, rest, ok := f.windowsRoot(path)
		if !ok {
			return normalized{}, false
		}
		out := root.appendTo(buf)
		return f.appendClean(out, len(out), rest, true), true
	}
	if f.deleted {
		path = strings.TrimSuffix(path, " (deleted)")
	}
	if path == "" || path[0] != '/' {
		return normalized{}, false
	}
	if unixClean(path) {
		return normalized{s: path}, true
	}
	return f.appendClean(buf, 0, path, false), true
}

// unixClean reports whether an absolute Unix path is already canonical: no
// empty, "." or ".." components and no trailing separator.
func unixClean(path string) bool {
	if path[len(path)-1] == '/' {
		return path == "/"
	}
	// Vectorized pre-check; only paths with a dot-prefixed name or a
	// doubled separator take the exact scan below.
	if !strings.Contains(path, "/.") && !strings.Contains(path, "//") {
		return true
	}
	for i := 0; i < len(path); i++ {
		if path[i] != '/' {
			continue
		}
		next := path[i+1:]
		if next[0] == '/' {
			return false
		}
		if next[0] == '.' && (len(next) == 1 || next[1] == '/' || next[1] == '.' && (len(next) == 2 || next[2] == '/')) {
			return false
		}
	}
	return true
}

// appendClean appends "/" and the cleaned components of rest to out[:root].
// ".." never climbs above the root.
func (f Flavor) appendClean(out []byte, root int, rest string, fold bool) normalized {
	out = out[:root]
	for len(rest) > 0 {
		end := 0
		for end < len(rest) && !f.isSep(rest[end]) {
			end++
		}
		component := rest[:end]
		if end < len(rest) {
			rest = rest[end+1:]
		} else {
			rest = ""
		}
		switch component {
		case "", ".":
			continue
		case "..":
			if i := lastSlash(out[root:]); i >= 0 {
				out = out[:root+i]
			}
			continue
		}
		out = append(out, '/')
		if fold {
			out = appendFold(out, component)
		} else {
			out = append(out, component...)
		}
	}
	if len(out) == root {
		out = append(out, '/')
	}
	return normalized{s: bytesString(out), root: root}
}

func lastSlash(b []byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == '/' {
			return i
		}
	}
	return -1
}

// winRoot is the root of an absolute Windows path: a prefix ("", "//" for
// UNC, "//?/" for device objects) and up to two names. It is kept in parts so
// that parsing never concatenates on the lookup path.
type winRoot struct {
	prefix string
	a, b   string
}

// appendTo appends the folded canonical root.
func (r winRoot) appendTo(out []byte) []byte {
	out = appendFold(append(out, r.prefix...), r.a)
	if r.b != "" {
		out = appendFold(append(out, '/'), r.b)
	}
	return out
}

// windowsRoot splits an absolute Windows path into its root and the
// remainder. Drive-relative (C:foo), root-relative (\foo) and relative
// paths are not absolute.
func (f Flavor) windowsRoot(path string) (root winRoot, rest string, ok bool) {
	sep := f.isSep
	switch {
	case len(path) >= 4 && sep(path[0]) && sep(path[3]) &&
		(sep(path[1]) && (path[2] == '?' || path[2] == '.') || path[1] == '?' && path[2] == '?'):
		// \\?\ (extended-length), \??\ (NT object manager) and \\.\
		// (device namespace) prefixes in front of a drive, UNC or device name.
		rest = path[4:]
		if hasFoldPrefix(rest, "UNC") && (len(rest) == 3 || sep(rest[3])) {
			return f.uncRoot(rest[3:])
		}
		if len(rest) >= 2 && isLetter(rest[0]) && rest[1] == ':' && (len(rest) == 2 || sep(rest[2])) {
			return winRoot{a: rest[:2]}, rest[2:], true
		}
		if hasFoldPrefix(rest, "GLOBALROOT") && len(rest) > 10 && sep(rest[10]) {
			return f.deviceRoot(rest[10:])
		}
		name, tail := splitFirst(rest, sep)
		if name == "" {
			return winRoot{}, "", false
		}
		return winRoot{prefix: "//?/", a: name}, tail, true
	case len(path) >= 8 && sep(path[0]) && hasFoldPrefix(path[1:], "Device") && sep(path[7]):
		return f.deviceRoot(path)
	case len(path) >= 2 && sep(path[0]) && sep(path[1]):
		return f.uncRoot(path[2:])
	case len(path) >= 3 && isLetter(path[0]) && path[1] == ':' && sep(path[2]):
		return winRoot{a: path[:2]}, path[2:], true
	}
	return winRoot{}, "", false
}

// uncRoot parses "server\share\rest" (after the leading separators).
func (f Flavor) uncRoot(path string) (winRoot, string, bool) {
	for len(path) > 0 && f.isSep(path[0]) {
		path = path[1:]
	}
	server, path := splitFirst(path, f.isSep)
	share, rest := splitFirst(path, f.isSep)
	if server == "" || share == "" || server == "." || server == "?" {
		return winRoot{}, "", false
	}
	return winRoot{prefix: "//", a: server, b: share}, rest, true
}

// deviceRoot parses "\Device\Name\rest" and maps a known device to its
// drive.
func (f Flavor) deviceRoot(path string) (winRoot, string, bool) {
	_, path = splitFirst(path, f.isSep) // leading separator
	kind, path := splitFirst(path, f.isSep)
	name, rest := splitFirst(path, f.isSep)
	if !strings.EqualFold(kind, "Device") || name == "" {
		return winRoot{}, "", false
	}
	if f.devices != nil {
		var buf [64]byte
		key := appendFold(append(appendFold(append(buf[:0], '\\'), kind), '\\'), name)
		if drive, ok := f.devices[bytesString(key)]; ok {
			return winRoot{a: drive}, rest, true
		}
	}
	return winRoot{prefix: "//?/", a: kind, b: name}, rest, true
}

func splitFirst(s string, sep func(byte) bool) (string, string) {
	for i := 0; i < len(s); i++ {
		if sep(s[i]) {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

func hasFoldPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// appendFold appends s case-folded the way Windows compares names: every
// rune is mapped to upper case, as the NTFS upcase table does.
func appendFold(out []byte, s string) []byte {
	// ASCII fast path: extend once and write in place.
	start := len(out)
	out = slices.Grow(out, len(s))[:start+len(s)]
	dst := out[start:]
	i := 0
	for ; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			break
		}
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
		}
		dst[i] = c
	}
	if i == len(s) {
		return out
	}
	out = out[:start+i]
	for i < len(s) {
		c := s[i]
		if c < utf8.RuneSelf {
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A'
			}
			out = append(out, c)
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			out = append(out, c)
		} else {
			out = utf8.AppendRune(out, unicode.ToUpper(r))
		}
		i += size
	}
	return out
}

// Equal reports whether two paths name the same file for f. Paths that are
// not absolute are compared as given.
func (f Flavor) Equal(a, b string) bool {
	var bufA, bufB [512]byte
	na, absA := f.normalize(bufA[:0], a)
	nb, absB := f.normalize(bufB[:0], b)
	if !absA || !absB {
		return absA == absB && a == b
	}
	return na.s == nb.s
}
