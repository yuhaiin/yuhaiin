package processpath

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

func matches(t *testing.T, f Flavor, pattern, path string) bool {
	t.Helper()
	b := NewBuilder(f)
	if _, err := b.Add(pattern, "list"); err != nil {
		t.Fatalf("Add(%q): %v", pattern, err)
	}
	return slices.Contains(b.Build().Match(path), "list")
}

func TestGlobMatching(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/opt/app/bin/app", "/opt/app/bin/app", true},
		{"/opt/app/bin/app", "/opt/app/bin/helper", false},
		{"/opt/app/**", "/opt/app/bin/app", true},
		{"/opt/app/**", "/opt/app/lib/sub/helper", true},
		{"/opt/app/**", "/opt/app-old/bin/app", false},
		{"/opt/app/**", "/opt/app", false}, // the directory itself is not below it
		{"/opt/app/**", "/opt/application/bin/app", false},
		{"**/aaa/**", "/opt/aaa/bin/app", true},
		{"**/aaa/**", "/aaa/bin/app", true},
		{"**/aaa/**", "/opt/x/aaa/lib/app", true},
		{"**/aaa/**", "/usr/local/aaa/lib/app", true},
		{"**/aaa/**", "/opt/example/aaa/subdir/bin/app", true},
		{"**/aaa/**", "/opt/aaab/bin/app", false},
		{"**/aaa/**", "/opt/x/aaa-backup/bin/app", false},
		{"**/aaa/**", "/opt/example/bin/aaa-app", false},
		{"**/aaa/**", "/opt/example/bin/aaa", false},
		{"**/Example*/bin/*", "/opt/ExampleApp/bin/helper", true},
		{"**/Example*/bin/*", "/opt/ExampleApp/tools/helper", false},
		{"**/Example*/bin/*", "/opt/ExampleApp/bin/sub/helper", false},
		{"**/Example*/bin/helper?.exe", "/x/Example1/bin/helper2.exe", true},
		{"**/Example*/bin/helper?.exe", "/x/Example1/bin/helper22.exe", false},
		{"**/Example*/bin/helper?.exe", "/x/Example1/bin/helper.exe", false},
		// ** at the start, middle and end.
		{"**/bin/curl", "/usr/bin/curl", true},
		{"**/bin/curl", "/bin/curl", true},
		{"**/bin/curl", "/usr/bin/curl2", false},
		{"/srv/**/tools/run", "/srv/tools/run", true},
		{"/srv/**/tools/run", "/srv/a/b/c/tools/run", true},
		{"/srv/**/tools/run", "/srv/a/tools/x/run", false},
		{"/srv/**/tools/run", "/srvx/tools/run", false},
		{"/a/**/b/**/c", "/a/b/c", true},
		{"/a/**/b/**/c", "/a/x/b/y/z/c", true},
		{"/a/**/b/**/c", "/a/x/c", false},
		{"/a/**/**/b", "/a/b", true},
		{"**", "/anything/at/all", true},
		{"/**", "/x", true},
		// * and ? never cross a separator.
		{"/opt/*/app", "/opt/x/app", true},
		{"/opt/*/app", "/opt/x/y/app", false},
		{"/opt/a?c", "/opt/abc", true},
		{"/opt/a?c", "/opt/a/c", false},
		{"/opt/a?c", "/opt/aéc", true}, // ? is one character, not one byte
		{"/opt/*", "/opt/.hidden", true},
		// Unix is case-sensitive.
		{"/Applications/ExampleEditor.app/**", "/applications/exampleeditor.app/Contents/MacOS/x", false},
		{"/opt/a/./b/../c", "/opt/a/c", true},
		{"/opt//a/", "/opt/a", true},
	}
	for _, tc := range cases {
		if got := matches(t, Linux, tc.pattern, tc.path); got != tc.want {
			t.Errorf("%q vs %q = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestMacApplicationBundle(t *testing.T) {
	for _, path := range []string{
		"/Applications/ExampleEditor.app/Contents/MacOS/ExampleEditor",
		"/Applications/ExampleEditor.app/Contents/Frameworks/Example Helper.app/Contents/MacOS/Example Helper",
		"/Applications/ExampleEditor.app/Contents/Frameworks/Example Renderer.app/Contents/MacOS/Example Renderer",
		"/Applications/ExampleEditor.app/Contents/Frameworks/Example GPU.app/Contents/MacOS/Example GPU",
	} {
		if !matches(t, Darwin, "/Applications/ExampleEditor.app/**", path) {
			t.Errorf("bundle pattern does not match %q", path)
		}
		if !matches(t, Darwin, "**/ExampleEditor.app/**", path) {
			t.Errorf("any-depth bundle pattern does not match %q", path)
		}
	}
	if matches(t, Darwin, "/Applications/ExampleEditor.app/**", "/Applications/ExampleEditor.app.bak/Contents/MacOS/x") {
		t.Error("bundle pattern matched a similarly named bundle")
	}
	// Volumes are ordinary directories on macOS.
	if !matches(t, Darwin, "/Volumes/External/Apps/**", "/Volumes/External/Apps/Tool.app/Contents/MacOS/Tool") {
		t.Error("volume path did not match")
	}
}

func TestWindowsMatching(t *testing.T) {
	cases := []struct {
		path, pattern string
		want          bool
	}{
		{`C:\Program Files\ExampleEditor\bin.exe`, `C:\Program Files\ExampleEditor\**`, true},
		{`c:\program files\exampleeditor\bin.exe`, `C:\Program Files\ExampleEditor\**`, true},
		{`C:/Program Files/ExampleEditor/bin.exe`, `C:\Program Files\ExampleEditor\**`, true},
		{`D:\Program Files\ExampleEditor\bin.exe`, `C:\Program Files\ExampleEditor\**`, false},
		{`D:\Program Files\ExampleEditor\bin.exe`, `**/Program Files/ExampleEditor/**`, true},
		{`C:\Program Files\ExampleEditor\bin.exe`, `**\Program Files\ExampleEditor\**`, true},
		{`\\?\C:\Program Files\ExampleEditor\bin.exe`, `C:\Program Files\ExampleEditor\**`, true},
		{`\??\C:\Program Files\ExampleEditor\bin.exe`, `C:\Program Files\ExampleEditor\**`, true},
		{`\\.\C:\Program Files\ExampleEditor\bin.exe`, `C:\Program Files\ExampleEditor\**`, true},
		{`\\server\share\ExampleEditor\bin.exe`, `**/ExampleEditor/**`, true},
		{`\\server\share\ExampleEditor\bin.exe`, `C:\ExampleEditor\**`, false},
		{`\\server\share\ExampleEditor\bin.exe`, `\\SERVER\Share\ExampleEditor\**`, true},
		{`\\?\UNC\server\share\ExampleEditor\bin.exe`, `\\server\share\ExampleEditor\**`, true},
		{`\\other\share\ExampleEditor\bin.exe`, `\\server\share\ExampleEditor\**`, false},
		{`C:\Program Files\ExampleEditor-old\bin.exe`, `C:\Program Files\ExampleEditor\**`, false},
		{`C:\Program Files\ExampleEditor\bin.exe`, `c:\program files\exampleeditor\bin.exe`, true},
		{`C:\Program Files\ExampleEditor\bin.exe`, `D:\Program Files\ExampleEditor\bin.exe`, false},
		{`C:\x\Example1\bin\HELPER2.EXE`, `**/Example*/bin/helper?.exe`, true},
		{`C:\Windows\System32\..\explorer.exe`, `C:\Windows\explorer.exe`, true},
		{`C:\..\..\Windows\explorer.exe`, `C:\Windows\explorer.exe`, true},
		{`C:\Program Files\Ünïcode\a.exe`, `C:\program files\üNÏCODE\**`, true},
		// Unknown device paths never equal a drive.
		{`\Device\HarddiskVolume3\Program Files\ExampleEditor\bin.exe`, `C:\Program Files\ExampleEditor\**`, false},
		{`\Device\HarddiskVolume3\Program Files\ExampleEditor\bin.exe`, `**/Program Files/ExampleEditor/**`, true},
		{`\Device\HarddiskVolume3\Program Files\ExampleEditor\bin.exe`, `\Device\HarddiskVolume3\Program Files\**`, true},
		{`\Device\HarddiskVolume4\Program Files\ExampleEditor\bin.exe`, `\Device\HarddiskVolume3\Program Files\**`, false},
		// Drive-relative and root-relative process paths only match exactly.
		{`C:relative\bin.exe`, `C:\relative\**`, false},
		{`\relative\bin.exe`, `**/relative/**`, false},
	}
	for _, tc := range cases {
		if got := matches(t, Windows, tc.pattern, tc.path); got != tc.want {
			t.Errorf("%q vs %q = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestWindowsDeviceTable(t *testing.T) {
	f := Windows.WithDevices(map[string]string{`\Device\HarddiskVolume3`: `C:`, `\Device\HarddiskVolume5`: `d:\`})
	for _, tc := range []struct {
		path, pattern string
		want          bool
	}{
		{`\Device\HarddiskVolume3\Program Files\ExampleEditor\bin.exe`, `C:\Program Files\ExampleEditor\**`, true},
		{`\device\harddiskvolume3\program files\exampleeditor\bin.exe`, `C:\Program Files\ExampleEditor\**`, true},
		{`\\?\GLOBALROOT\Device\HarddiskVolume3\Program Files\ExampleEditor\bin.exe`, `C:\Program Files\ExampleEditor\**`, true},
		{`\Device\HarddiskVolume5\Program Files\ExampleEditor\bin.exe`, `C:\Program Files\ExampleEditor\**`, false},
		{`D:\Program Files\ExampleEditor\bin.exe`, `\Device\HarddiskVolume5\Program Files\**`, true},
		{`\Device\HarddiskVolume9\Program Files\ExampleEditor\bin.exe`, `C:\Program Files\ExampleEditor\**`, false},
	} {
		if got := matches(t, f, tc.pattern, tc.path); got != tc.want {
			t.Errorf("%q vs %q = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		name   string
		flavor Flavor
		path   string
		want   string
		abs    bool
	}{
		{"unix", Linux, "/usr/bin/curl", "/usr/bin/curl", true},
		{"unix root", Linux, "/", "/", true},
		{"unix duplicate separator", Linux, "/usr//bin///curl", "/usr/bin/curl", true},
		{"unix dot", Linux, "/usr/./bin/./curl", "/usr/bin/curl", true},
		{"unix dotdot", Linux, "/usr/lib/../bin/curl", "/usr/bin/curl", true},
		{"unix dotdot above root", Linux, "/../../usr/bin", "/usr/bin", true},
		{"unix trailing separator", Linux, "/usr/bin/", "/usr/bin", true},
		{"unix dot-prefixed names stay", Linux, "/opt/.app/..x/...", "/opt/.app/..x/...", true},
		{"unix backslash is a name character", Linux, `/opt/a\b`, `/opt/a\b`, true},
		{"unix case preserved", Darwin, "/Applications/A.app", "/Applications/A.app", true},
		{"macos volume", Darwin, "/Volumes/Data/bin/x", "/Volumes/Data/bin/x", true},
		{"linux deleted", Linux, "/usr/bin/old (deleted)", "/usr/bin/old", true},
		{"darwin keeps deleted text", Darwin, "/tmp/x (deleted)", "/tmp/x (deleted)", true},
		{"unix relative", Linux, "usr/bin", "usr/bin", false},
		{"android package", Linux, "com.example.app", "com.example.app", false},
		{"windows drive", Windows, `C:\Program Files\A\a.exe`, "C:/PROGRAM FILES/A/A.EXE", true},
		{"windows drive case", Windows, `c:\program files\a\a.exe`, "C:/PROGRAM FILES/A/A.EXE", true},
		{"windows forward slashes", Windows, `C:/Program Files//A/./a.exe`, "C:/PROGRAM FILES/A/A.EXE", true},
		{"windows drive root", Windows, `C:\`, "C:/", true},
		{"windows extended", Windows, `\\?\C:\A\a.exe`, "C:/A/A.EXE", true},
		{"windows nt namespace", Windows, `\??\C:\A\a.exe`, "C:/A/A.EXE", true},
		{"windows device namespace", Windows, `\\.\C:\A\a.exe`, "C:/A/A.EXE", true},
		{"windows unc", Windows, `\\Server\Share\A\a.exe`, "//SERVER/SHARE/A/A.EXE", true},
		{"windows extended unc", Windows, `\\?\UNC\Server\Share\A\a.exe`, "//SERVER/SHARE/A/A.EXE", true},
		{"windows unc dotdot stays in share", Windows, `\\server\share\..\..\a.exe`, "//SERVER/SHARE/A.EXE", true},
		{"windows device", Windows, `\Device\HarddiskVolume3\A\a.exe`, "//?/DEVICE/HARDDISKVOLUME3/A/A.EXE", true},
		{"windows volume guid", Windows, `\\?\Volume{1234}\A\a.exe`, "//?/VOLUME{1234}/A/A.EXE", true},
		{"windows drive relative", Windows, `C:relative\a.exe`, `C:relative\a.exe`, false},
		{"windows root relative", Windows, `\A\a.exe`, `\A\a.exe`, false},
		{"windows unc without share", Windows, `\\server`, `\\server`, false},
		{"windows pseudo process", Windows, ":System", ":System", false},
		{"windows no deleted handling", Windows, `C:\a (deleted)`, "C:/A (DELETED)", true},
	}
	for _, tc := range cases {
		got, abs := tc.flavor.Normalize(tc.path)
		if got != tc.want || abs != tc.abs {
			t.Errorf("%s: Normalize(%q) = %q, %v; want %q, %v", tc.name, tc.path, got, abs, tc.want, tc.abs)
		}
	}
}

func TestCompileValidation(t *testing.T) {
	cases := []struct {
		flavor  Flavor
		entry   string
		kind    Kind
		problem string // substring of the error; empty means valid
	}{
		{Linux, "**foo", 0, "whole path component"},
		{Linux, "foo**bar", 0, "whole path component"},
		{Linux, "/opt/foo**", 0, "whole path component"},
		{Linux, "/opt/**x/y", 0, "whole path component"},
		{Linux, "foo/**", 0, "absolute path or start with **/"},
		{Linux, "chrome*", 0, "absolute path or start with **/"},
		{Linux, "bin/curl", 0, "relative paths never match"},
		{Linux, "/..", 0, "climbs above the root"},
		{Linux, "**/../x", 0, "cannot follow a wildcard"},
		{Linux, "/opt/*/../x", 0, "cannot follow a wildcard"},
		{Linux, "/usr/bin/curl", KindExact, ""},
		{Linux, "com.example.app", KindExact, ""},
		{Linux, "/opt/app/**", KindGlob, ""},
		{Linux, "**/aaa/**", KindGlob, ""},
		{Linux, "/opt/[abc]/{x,y}", KindExact, ""}, // no classes or braces: literal text
		// Windows entries on Unix are validated, then inert.
		{Linux, `C:\Program Files\ExampleEditor\**`, KindForeign, ""},
		{Linux, `\\server\share\x.exe`, KindForeign, ""},
		{Linux, `C:\Program Files\foo**`, 0, "whole path component"},
		{Linux, `C:relative`, 0, "drive-relative"},
		{Darwin, `C:\Windows\explorer.exe`, KindForeign, ""},
		{Windows, `/Applications/ExampleEditor.app/**`, KindForeign, ""},
		{Windows, `/opt/**x`, 0, "whole path component"},
		{Windows, `C:\Program Files\ExampleEditor\**`, KindGlob, ""},
		{Windows, `**/Program Files/ExampleEditor/**`, KindGlob, ""},
		{Windows, `C:\Windows\explorer.exe`, KindExact, ""},
		{Windows, `:System`, KindExact, ""},
		{Windows, `\\?\C:\Program Files\**`, KindGlob, ""},
		{Windows, `//server/share/app/**`, KindGlob, ""},
		{Windows, `\Program Files\ExampleEditor\**`, 0, "no drive letter"},
		{Windows, `C:relative\path`, 0, "drive-relative"},
		{Windows, `*:\Program Files\**`, 0, "wildcard drive letters"},
		{Windows, `\\*\share\x.exe`, 0, "server, share"},
		{Windows, `Program Files\x.exe`, 0, "relative paths never match"},
	}
	for _, tc := range cases {
		p, err := tc.flavor.Compile(tc.entry)
		if tc.problem == "" {
			if err != nil {
				t.Errorf("Compile(%q) = %v", tc.entry, err)
			} else if p.Kind() != tc.kind {
				t.Errorf("Compile(%q) kind = %v, want %v", tc.entry, p.Kind(), tc.kind)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.problem) {
			t.Errorf("Compile(%q) error = %v, want %q", tc.entry, err, tc.problem)
		}
	}
}

func TestIndexLists(t *testing.T) {
	b := NewBuilder(Linux)
	for _, entry := range []struct{ value, list string }{
		{"/usr/bin/curl", "a"},
		{"/usr/bin/curl", "a"}, // duplicate in one list
		{"/usr/bin/curl", "b"},
		{"/usr/**", "a"}, // same list through a glob
		{"**/bin/*", "c"},
		{"**/bin/*", "d"}, // one compiled pattern, two lists
		{"/opt/**", "e"},
	} {
		if _, err := b.Add(entry.value, entry.list); err != nil {
			t.Fatal(err)
		}
	}
	b.Register("empty")
	ix := b.Build()
	got := slices.Clone(ix.Match("/usr/bin/curl"))
	slices.Sort(got)
	if want := []string{"a", "b", "c", "d"}; !slices.Equal(got, want) {
		t.Fatalf("Match = %v, want %v", got, want)
	}
	if got := ix.Match("/srv/x"); got != nil {
		t.Fatalf("Match miss = %v", got)
	}
	if s := ix.Stats(); s.Exact != 1 || s.Globs != 3 || s.Lists != 6 || s.Entries != 7 {
		t.Fatalf("Stats = %+v", s)
	}
	if !slices.Contains(ix.Lists(), "empty") {
		t.Fatal("registered empty list missing")
	}
	if ix.Empty() {
		t.Fatal("index reported empty")
	}
	foreignOnly := NewBuilder(Linux)
	if _, err := foreignOnly.Add(`C:\a.exe`, "w"); err != nil {
		t.Fatal(err)
	}
	if !foreignOnly.Build().Empty() {
		t.Fatal("an index of foreign entries can never match and must be empty")
	}
}

// TestIndexAgreesWithLinearScan checks that candidate selection never drops
// a match: every lookup equals evaluating every pattern.
func TestIndexAgreesWithLinearScan(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	words := []string{"a", "aa", "aaa", "bin", "lib", "Example", "ExampleApp", "app.exe", "x", "helper1"}
	component := func() string {
		w := words[rng.IntN(len(words))]
		switch rng.IntN(6) {
		case 0:
			return w + "*"
		case 1:
			return "*" + w
		case 2:
			return w[:len(w)/2] + "?" + w[len(w)/2+1:]
		case 3:
			return "**"
		}
		return w
	}
	for _, f := range []Flavor{Linux, Windows} {
		root := func() string {
			if f.windows {
				return []string{`C:`, `D:`, `\\srv\share`}[rng.IntN(3)]
			}
			return ""
		}
		patterns := map[string]string{} // list -> pattern
		b := NewBuilder(f)
		for i := range 400 {
			var parts []string
			if rng.IntN(3) == 0 {
				parts = append(parts, "**")
			} else {
				parts = append(parts, root())
			}
			for range 1 + rng.IntN(5) {
				parts = append(parts, component())
			}
			pattern := strings.Join(parts, "/")
			if _, err := b.Add(pattern, fmt.Sprint(i)); err == nil {
				patterns[fmt.Sprint(i)] = pattern
			}
		}
		ix := b.Build()
		if ix.Stats().Globs < 200 {
			t.Fatalf("too few valid patterns: %+v", ix.Stats())
		}
		for range 3000 {
			parts := []string{root()}
			for range 1 + rng.IntN(7) {
				parts = append(parts, words[rng.IntN(len(words))])
			}
			path := strings.Join(parts, "/")
			got := slices.Clone(ix.Match(path))
			slices.Sort(got)
			var want []string
			for list, pattern := range patterns {
				if linearMatch(t, f, pattern, path) {
					want = append(want, list)
				}
			}
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("windows=%v %q: index %v, linear scan %v", f.windows, path, got, want)
			}
		}
	}
}

// linearMatch evaluates one pattern without any index.
func linearMatch(t *testing.T, f Flavor, pattern, path string) bool {
	t.Helper()
	p, err := f.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	canonical, abs := f.Normalize(path)
	switch p.kind {
	case KindExact:
		return canonical == p.key
	case KindGlob:
		if !abs {
			return false
		}
		var buf [512]byte
		np, _ := f.normalize(buf[:0], path)
		if !p.floating && np.rootString() != p.root {
			return false
		}
		return matchSegments(p.segs, components{s: np.s, spans: splitSpans(nil, np.s, np.root+1)})
	}
	return false
}

func TestMatchAllocations(t *testing.T) {
	b := NewBuilder(Linux)
	for i := range 1000 {
		_, _ = b.Add(fmt.Sprintf("/opt/v%d/bin/app", i), "exact")
		_, _ = b.Add(fmt.Sprintf("**/pkg%d/**", i), "glob")
	}
	_, _ = b.Add("/usr/bin/curl", "curl")
	linux := b.Build()
	w := NewBuilder(Windows)
	_, _ = w.Add(`C:\Windows\System32\svchost.exe`, "svc")
	_, _ = w.Add(`C:\Program Files\ExampleEditor\**`, "editor")
	windows := w.Build()
	for _, tc := range []struct {
		ix   *Index
		path string
	}{
		{linux, "/usr/bin/curl"},
		{linux, "/usr/bin/wget"},
		{linux, "/srv/pkg42/bin/x"},
		{linux, "/srv/./pkg42//bin/x"},
		{windows, `c:\windows\system32\SVCHOST.EXE`},
		{windows, `C:\Program Files\ExampleEditor\bin\editor.exe`},
		{windows, `\\?\C:\Program Files\ExampleEditor\bin\editor.exe`},
	} {
		if n := testing.AllocsPerRun(100, func() { _ = tc.ix.Match(tc.path) }); n != 0 {
			t.Errorf("Match(%q) allocates %v times", tc.path, n)
		}
	}
}
