package route

// Process matcher benchmarks. This file must stay identical between the
// baseline (exact-only matcher) and the glob implementation so benchstat can
// compare them; only process_matcher_bench_adapter_test.go differs. On the
// baseline, glob patterns are stored as plain exact strings, so glob queries
// measure what an exact-only lookup costs for the same input, not a match.

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type benchProcessEntry struct {
	value string
	list  string
}

var benchPatternCounts = []int{1, 10, 100, 1000, 10000}

func benchProcessContext(path string) context.Context {
	ctx := netapi.WithContext(context.Background())
	ctx.SetProcess(path, 1, 0)
	return ctx
}

func benchExactEntries(n int) []benchProcessEntry {
	entries := make([]benchProcessEntry, 0, n)
	for i := range n {
		entries = append(entries, benchProcessEntry{fmt.Sprintf("/opt/vendor%05d/bin/app", i), fmt.Sprintf("list%d", i%16)})
	}
	return entries
}

// benchGlobEntries cycles through the pattern shapes users write: an
// application directory, a directory at any depth, a partial component with
// a fixed child and a mid-pattern **.
func benchGlobEntries(n int) []benchProcessEntry {
	entries := make([]benchProcessEntry, 0, n)
	for i := range n {
		var value string
		switch i % 4 {
		case 0:
			value = fmt.Sprintf("/opt/vendor%05d/**", i)
		case 1:
			value = fmt.Sprintf("**/pkg%05d/**", i)
		case 2:
			value = fmt.Sprintf("**/Example%05d*/bin/*", i)
		case 3:
			value = fmt.Sprintf("/usr/lib/app%05d/**/helper", i)
		}
		entries = append(entries, benchProcessEntry{value, fmt.Sprintf("list%d", i%16)})
	}
	return entries
}

func benchMixedEntries(n int) []benchProcessEntry {
	half := max(n/2, 1)
	entries := benchExactEntries(half)
	for _, entry := range benchGlobEntries(n - half) {
		entry.value = strings.Replace(entry.value, "vendor", "gvendor", 1)
		entries = append(entries, entry)
	}
	return entries
}

type benchProcessQuery struct {
	name string
	path string
}

func runProcessQueries(b *testing.B, matcher *processMatcher, queries []benchProcessQuery) {
	for _, query := range queries {
		b.Run(query.name, func(b *testing.B) {
			ctx := benchProcessContext(query.path)
			b.ReportAllocs()
			for b.Loop() {
				_ = matcher.Search(ctx, nil)
			}
		})
	}
}

// BenchmarkProcessMatcherBasic covers the single-shape cases against a
// background of 1,000 unrelated entries of each kind.
func BenchmarkProcessMatcherBasic(b *testing.B) {
	background := append(benchExactEntries(1000), benchGlobEntries(1000)...)
	b.Run("exact", func(b *testing.B) {
		entries := append([]benchProcessEntry{}, background...)
		entries = append(entries,
			benchProcessEntry{"/usr/bin/curl", "tools"},
			benchProcessEntry{"/usr/bin/shared", "a"},
			benchProcessEntry{"/usr/bin/shared", "b"},
			benchProcessEntry{"/usr/bin/shared", "c"},
		)
		runProcessQueries(b, benchProcessMatcher(false, entries), []benchProcessQuery{
			{"hit", "/usr/bin/curl"},
			{"miss", "/usr/bin/wget"},
			{"multi_list_hit", "/usr/bin/shared"},
		})
	})
	b.Run("directory", func(b *testing.B) {
		entries := append([]benchProcessEntry{}, background...)
		entries = append(entries, benchProcessEntry{"/opt/app/**", "app"})
		runProcessQueries(b, benchProcessMatcher(false, entries), []benchProcessQuery{
			{"hit", "/opt/app/bin/app"},
			{"deep_hit", "/opt/app/lib/a/b/c/d/e/f/g/helper"},
			{"similar_miss", "/opt/app-old/bin/app"},
		})
	})
	b.Run("glob", func(b *testing.B) {
		entries := append([]benchProcessEntry{}, background...)
		entries = append(entries,
			benchProcessEntry{"**/aaa/**", "aaa"},
			benchProcessEntry{"**/Example*/bin/*", "example"},
			benchProcessEntry{"/srv/**/tools/run?", "middle"},
		)
		runProcessQueries(b, benchProcessMatcher(false, entries), []benchProcessQuery{
			{"any_depth_hit", "/opt/x/aaa/lib/app"},
			{"any_depth_similar_miss", "/opt/x/aaa-backup/lib/app"},
			{"partial_component_hit", "/opt/ExampleApp/bin/helper"},
			{"partial_component_miss", "/opt/ExampleApp/tools/helper"},
			{"middle_double_star_hit", "/srv/a/b/c/tools/run1"},
			{"miss", "/home/user/.local/bin/tool"},
		})
	})
	b.Run("windows", func(b *testing.B) {
		entries := append([]benchProcessEntry{}, background...)
		entries = append(entries,
			benchProcessEntry{`C:\Program Files\ExampleEditor\**`, "fixed"},
			benchProcessEntry{`**/Program Files/ExampleTool/**`, "anydrive"},
			benchProcessEntry{`C:\Windows\System32\svchost.exe`, "exact"},
		)
		runProcessQueries(b, benchProcessMatcher(true, entries), []benchProcessQuery{
			{"exact_hit", `C:\Windows\System32\svchost.exe`},
			{"exact_case_hit", `c:\windows\system32\SVCHOST.EXE`},
			{"exact_miss", `C:\Windows\System32\notepad.exe`},
			{"drive_fixed_hit", `C:\Program Files\ExampleEditor\bin\editor.exe`},
			{"drive_case_hit", `c:\program files\exampleeditor\bin\editor.exe`},
			{"drive_other_miss", `D:\Program Files\ExampleEditor\bin\editor.exe`},
			{"any_drive_hit", `D:\Program Files\ExampleTool\tool.exe`},
			{"unc_hit", `\\server\share\Program Files\ExampleTool\tool.exe`},
			{"extended_hit", `\\?\C:\Program Files\ExampleEditor\bin\editor.exe`},
		})
	})
}

// BenchmarkProcessMatcherScale measures how lookups scale with the pattern
// count.
func BenchmarkProcessMatcherScale(b *testing.B) {
	for _, n := range benchPatternCounts {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			mid := n / 2
			b.Run("exact", func(b *testing.B) {
				runProcessQueries(b, benchProcessMatcher(false, benchExactEntries(n)), []benchProcessQuery{
					{"hit", fmt.Sprintf("/opt/vendor%05d/bin/app", mid)},
					{"miss", "/opt/unknown/bin/app"},
				})
			})
			b.Run("glob", func(b *testing.B) {
				dir := mid - mid%4
				runProcessQueries(b, benchProcessMatcher(false, benchGlobEntries(n)), []benchProcessQuery{
					{"hit", fmt.Sprintf("/opt/vendor%05d/bin/app", dir)},
					{"deep_hit", fmt.Sprintf("/opt/vendor%05d/a/b/c/d/e/f/g/h/i/j/k/l/app", dir)},
					{"miss", "/home/user/.local/bin/tool"},
					{"similar_miss", fmt.Sprintf("/opt/vendor%05d-old/bin/app", dir)},
				})
			})
			b.Run("mixed", func(b *testing.B) {
				half := max(n/2, 1)
				runProcessQueries(b, benchProcessMatcher(false, benchMixedEntries(n)), []benchProcessQuery{
					{"exact_hit", fmt.Sprintf("/opt/vendor%05d/bin/app", half/2)},
					{"glob_hit", fmt.Sprintf("/opt/gvendor%05d/bin/app", half-half%4)},
					{"miss", "/home/user/.local/bin/tool"},
				})
			})
		})
	}
}

// BenchmarkProcessMatcherPathShape varies path length and depth.
func BenchmarkProcessMatcherPathShape(b *testing.B) {
	many := "/" + strings.Repeat("d/", 60) + "app"
	deep := "/opt/aaa/" + strings.Repeat("level/", 18) + "app"
	longWindows := `C:\Program Files\` + strings.Repeat(`Very Long Directory Name\`, 9) + `bin\app.exe`
	unix := append(benchGlobEntries(1000), benchExactEntries(1000)...)
	unix = append(unix, benchProcessEntry{"**/aaa/**", "aaa"}, benchProcessEntry{"/bin/a", "short"})
	runProcessQueries(b, benchProcessMatcher(false, unix), []benchProcessQuery{
		{"short", "/bin/a"},
		{"application", "/Applications/ExampleEditor.app/Contents/MacOS/ExampleEditor"},
		{"deep", deep},
		{"many_components", many},
	})
	windows := append(benchGlobEntries(1000), benchProcessEntry{`C:\Program Files\**\bin\app.exe`, "long"})
	runProcessQueries(b, benchProcessMatcher(true, windows), []benchProcessQuery{
		{"long_windows", longWindows},
	})
}

// BenchmarkProcessMatcherParallel searches through Lists, which is what the
// routing path does for every connection.
func BenchmarkProcessMatcherParallel(b *testing.B) {
	entries := append(benchExactEntries(1000), benchGlobEntries(1000)...)
	entries = append(entries, benchProcessEntry{"/usr/bin/curl", "tools"}, benchProcessEntry{"**/aaa/**", "aaa"})
	lists := benchProcessLists(benchProcessMatcher(false, entries))
	for _, query := range []benchProcessQuery{{"exact_hit", "/usr/bin/curl"}, {"glob_hit", "/opt/x/aaa/lib/app"}, {"miss", "/home/user/bin/tool"}} {
		b.Run(query.name, func(b *testing.B) {
			ctx := benchProcessContext(query.path)
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_ = lists.ProcessTrie().Search(ctx, nil)
				}
			})
		})
	}
}

// BenchmarkProcessMatcherBuild measures configuration-time cost: index
// construction and the heap retained by the finished index.
func BenchmarkProcessMatcherBuild(b *testing.B) {
	run := func(name string, entries []benchProcessEntry) {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			var retained uint64
			for b.Loop() {
				var before, after runtime.MemStats
				runtime.GC()
				runtime.ReadMemStats(&before)
				matcher := benchProcessMatcher(false, entries)
				runtime.GC()
				runtime.ReadMemStats(&after)
				retained = after.HeapAlloc - min(before.HeapAlloc, after.HeapAlloc)
				runtime.KeepAlive(matcher)
			}
			b.ReportMetric(float64(retained), "retained-B")
		})
	}
	for _, n := range benchPatternCounts {
		run(fmt.Sprintf("exact/n=%d", n), benchExactEntries(n))
		run(fmt.Sprintf("glob/n=%d", n), benchGlobEntries(n))
	}
	shared := make([]benchProcessEntry, 0, 1000)
	for i := range 1000 {
		shared = append(shared, benchProcessEntry{"/usr/bin/shared", fmt.Sprintf("list%d", i)})
	}
	run("one_path_many_lists", shared)
	duplicates := make([]benchProcessEntry, 0, 10000)
	for i := range 10000 {
		duplicates = append(duplicates, benchProcessEntry{fmt.Sprintf("**/dup%d/**", i%10), fmt.Sprintf("list%d", i%7)})
	}
	run("duplicate_patterns", duplicates)
}
