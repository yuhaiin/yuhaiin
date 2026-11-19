package route

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/route/processpath"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

// Route tests use Unix paths; pin the syntax so they hold on Windows too.
// Windows paths are covered by TestWindowsProcessRules and processpath.
func init() { processPathFlavor = func() processpath.Flavor { return processpath.Linux } }

func useProcessFlavor(t *testing.T, flavor processpath.Flavor) {
	old := processPathFlavor
	processPathFlavor = func() processpath.Flavor { return flavor }
	t.Cleanup(func() { processPathFlavor = old })
}

// processListBook is a mutable in-memory list store.
type processListBook struct {
	mu    sync.Mutex
	lists map[string]contractroute.RouteListDetail
}

func newProcessListBook(lists ...contractroute.RouteListDetail) *processListBook {
	b := &processListBook{lists: map[string]contractroute.RouteListDetail{}}
	for _, list := range lists {
		b.lists[list.ID] = list
	}
	return b
}

func (b *processListBook) set(list contractroute.RouteListDetail) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lists[list.ID] = list
}

func (b *processListBook) ListRouteListDetails(context.Context) ([]contractroute.RouteListDetail, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var lists []contractroute.RouteListDetail
	for _, list := range b.lists {
		lists = append(lists, list)
	}
	return lists, nil
}

func (b *processListBook) GetRouteList(_ context.Context, id string) (contractroute.RouteListDetail, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if list, ok := b.lists[id]; ok {
		return list, nil
	}
	return contractroute.RouteListDetail{}, errors.New("not found")
}

func (*processListBook) SaveRouteList(context.Context, contractroute.RouteListDetail, int64) error {
	return nil
}

func localProcessList(id string, entries ...string) contractroute.RouteListDetail {
	return contractroute.RouteListDetail{ID: id, Name: id, Type: "process",
		Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: entries}}}
}

func processRule(id, list, mode string) contractroute.RouteRule {
	return contractroute.RouteRule{ID: id, Name: id, Mode: mode,
		Rules: []contractroute.RuleExpr{{Type: "process", Process: &contractroute.ListRef{List: list}}}}
}

func processMatchContext(t *testing.T, path string) (*netapi.Context, netapi.Address) {
	t.Helper()
	ctx := netapi.WithContext(t.Context())
	ctx.SetProcess(path, 7, 0)
	addr, err := netapi.ParseAddressPort("tcp", "192.0.2.1", 443)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Destination = addr
	return ctx, addr
}

func matchedRule(t *testing.T, m *Matchers, path string) string {
	t.Helper()
	ctx, addr := processMatchContext(t, path)
	m.Match(ctx, addr)
	id, _ := ctx.MatchedRule()
	return id
}

func searchLists(m *Matchers, path string) []string {
	ctx := netapi.WithContext(context.Background())
	ctx.SetProcess(path, 7, 0)
	lists := slices.Clone(m.list.ProcessTrie().Search(ctx, nil))
	slices.Sort(lists)
	return lists
}

func TestProcessRulesMatchExactAndGlobEntries(t *testing.T) {
	m := newTestMatchers(t)
	m.list.lists = newProcessListBook(
		localProcessList("tools", "/usr/bin/curl", "# a comment", "", "/usr/bin/wget  # trailing comment"),
		localProcessList("editor", "/Applications/ExampleEditor.app/**", "/usr/bin/curl", "/usr/bin/curl"),
		localProcessList("aaa", "**/aaa/**"),
		localProcessList("mixed", "**/Example*/bin/*", `C:\Program Files\ExampleEditor\**`),
	)
	if err := m.Update(
		processRule("tools-rule", "tools", "direct"),
		processRule("editor-rule", "editor", "block"),
		processRule("aaa-rule", "aaa", "direct"),
		processRule("mixed-rule", "mixed", "direct"),
		alwaysRule("fallback", "proxy", contractroute.Target{}),
	); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, rule string
		lists      []string
	}{
		{"/usr/bin/curl", "tools-rule", []string{"editor", "tools"}},
		{"/usr/bin/wget", "tools-rule", []string{"tools"}},
		{"/usr//bin/./curl", "tools-rule", []string{"editor", "tools"}},
		{"/Applications/ExampleEditor.app/Contents/Frameworks/Example Helper.app/Contents/MacOS/Example Helper", "editor-rule", []string{"editor"}},
		{"/opt/x/aaa/lib/app", "aaa-rule", []string{"aaa"}},
		{"/opt/x/aaa-backup/lib/app", "fallback", nil},
		{"/opt/ExampleApp/bin/helper", "mixed-rule", []string{"mixed"}},
		{"/opt/aaa/ExampleApp/bin/helper", "aaa-rule", []string{"aaa", "mixed"}},
		{"/opt/ExampleApp/aaa/bin/helper", "aaa-rule", []string{"aaa"}},
		{"/usr/bin/curl2", "fallback", nil},
		{"", "fallback", nil}, // no process path: never guessed
		{"curl", "fallback", nil},
	} {
		if got := matchedRule(t, m, tc.path); got != tc.rule {
			t.Errorf("%q matched rule %q, want %q", tc.path, got, tc.rule)
		}
		if got := searchLists(m, tc.path); !slices.Equal(got, tc.lists) {
			t.Errorf("%q matched lists %v, want %v", tc.path, got, tc.lists)
		}
	}
	if len(m.listIssues) != 0 {
		t.Fatalf("unexpected issues: %+v", m.listIssues)
	}
	// The Windows entry is inert on this host and the rule history names the
	// rule that matched.
	ctx, addr := processMatchContext(t, "/opt/x/aaa/lib/app")
	m.Match(ctx, addr)
	if id, name := ctx.MatchedRule(); id != "aaa-rule" || name != "aaa-rule" {
		t.Fatalf("history = %q %q", id, name)
	}
}

func TestProcessListUpdateAppliesNewPatterns(t *testing.T) {
	m := newTestMatchers(t)
	book := newProcessListBook(localProcessList("apps", "/opt/app/bin/app"))
	m.list.lists = book
	rules := []contractroute.RouteRule{processRule("apps-rule", "apps", "direct"), alwaysRule("fallback", "proxy", contractroute.Target{})}
	if err := m.Update(rules...); err != nil {
		t.Fatal(err)
	}
	if got := matchedRule(t, m, "/opt/app/lib/helper"); got != "fallback" {
		t.Fatalf("before update: %q", got)
	}
	before := m.list.ProcessTrie()
	book.set(localProcessList("apps", "/opt/app/**"))
	if err := m.Update(rules...); err != nil {
		t.Fatal(err)
	}
	if got := matchedRule(t, m, "/opt/app/lib/helper"); got != "apps-rule" {
		t.Fatalf("after update: %q", got)
	}
	// The old index is never modified: a reader holding it sees old data.
	ctx := netapi.WithContext(t.Context())
	ctx.SetProcess("/opt/app/lib/helper", 1, 0)
	if got := before.Search(ctx, nil); got != nil {
		t.Fatalf("old index changed: %v", got)
	}
	// Re-applying identical data reuses the index.
	installed := m.list.ProcessTrie()
	if err := m.Update(rules...); err != nil {
		t.Fatal(err)
	}
	if m.list.ProcessTrie() != installed {
		t.Fatal("unchanged lists rebuilt the process index")
	}
}

func TestInvalidProcessEntriesAreReportedAndKeepValidEntries(t *testing.T) {
	m := newTestMatchers(t)
	m.list.lists = newProcessListBook(localProcessList("apps", "/opt/app/**", "foo**bar", "/srv/**x"))
	rules := []contractroute.RouteRule{processRule("apps-rule", "apps", "direct"), alwaysRule("fallback", "proxy", contractroute.Target{})}
	for range 2 { // the second apply reuses the index and must report again
		if err := m.Update(rules...); err != nil {
			t.Fatal(err)
		}
		if len(m.listIssues) != 1 {
			t.Fatalf("issues = %+v", m.listIssues)
		}
		issue := m.listIssues[0]
		if issue.ID != "apps" || !strings.Contains(issue.Error, `line 2: invalid process pattern "foo**bar"`) || !strings.Contains(issue.Error, "line 3:") {
			t.Fatalf("issue = %+v", issue)
		}
		// The list cannot prove absence any more, so the rule is degraded,
		// but valid entries still match.
		if len(m.degradedRules) != 1 {
			t.Fatalf("degraded = %+v", m.degradedRules)
		}
		if got := matchedRule(t, m, "/opt/app/bin/app"); got != "apps-rule" {
			t.Fatalf("valid entry did not match: %q", got)
		}
	}
}

func TestStrictCandidateWithInvalidProcessEntriesKeepsRunningIndex(t *testing.T) {
	m := newTestMatchers(t)
	m.list.lists = newProcessListBook(localProcessList("apps", "/opt/app/**"))
	rules := []contractroute.RouteRule{processRule("apps-rule", "apps", "direct"), alwaysRule("fallback", "proxy", contractroute.Target{})}
	if err := m.Update(rules...); err != nil {
		t.Fatal(err)
	}
	running := m.list.ProcessTrie()
	snapshot := plainstore.RouteSnapshot{Revision: 2, Lists: []contractroute.RouteListDetail{localProcessList("apps", "/opt/app/**", "/opt/**bad")}}
	for _, rule := range rules {
		snapshot.Rules = append(snapshot.Rules, plainstore.RouteRuleEntry{Rule: rule})
	}
	ctx := context.WithValue(t.Context(), completeCandidateKey{}, true)
	err := m.UpdateSnapshot(ctx, snapshot, func(context.Context, uint64, func()) error {
		t.Fatal("an invalid candidate was activated")
		return nil
	}, nil, func() {})
	if err == nil {
		t.Fatal("candidate with an invalid pattern was accepted")
	}
	if m.list.ProcessTrie() != running {
		t.Fatal("rejected candidate replaced the running process index")
	}
	if got := matchedRule(t, m, "/opt/app/bin/app"); got != "apps-rule" {
		t.Fatalf("running rule lost: %q", got)
	}
}

func TestRemoteProcessListUsesGlobs(t *testing.T) {
	m := newTestMatchers(t)
	m.list.downloader = NewDownloader(t.TempDir(), func() netapi.Proxy { return direct.Default })
	file := filepath.Join(t.TempDir(), "processes.txt")
	if err := os.WriteFile(file, []byte("# shared list\n/usr/bin/curl\n**/aaa/**\nC:\\Program Files\\ExampleEditor\\**\nnot**valid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	remote := contractroute.RouteListDetail{ID: "remote", Name: "remote", Type: "process",
		Source: contractroute.ListSource{Type: "remote", Remote: &contractroute.RemoteSource{URLs: []string{fileURL(file)}}}}
	m.list.lists = newProcessListBook(remote)
	if err := m.Update(processRule("remote-rule", "remote", "direct"), alwaysRule("fallback", "proxy", contractroute.Target{})); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"/usr/bin/curl": "remote-rule", "/opt/aaa/bin/x": "remote-rule"} {
		if got := matchedRule(t, m, path); got != want {
			t.Errorf("%q matched %q, want %q", path, got, want)
		}
	}
	if len(m.listIssues) != 1 || !strings.Contains(m.listIssues[0].Error, `"not**valid"`) {
		t.Fatalf("issues = %+v", m.listIssues)
	}
}

func TestProcessLookupModesWithGlobLists(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		wantRule string
		lookup   bool
	}{
		{"off", "fallback", false},
		{"rules_only", "apps-rule", true},
		{"always", "apps-rule", true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			router, host := processScopeRoute(t, tc.mode)
			router.ms.list.lists = newProcessListBook(localProcessList("ssh-tools", "/opt/app/**"))
			if err := router.ms.Update(processRule("apps-rule", "ssh-tools", "direct"), alwaysRule("fallback", "proxy", contractroute.Target{})); err != nil {
				t.Fatal(err)
			}
			host.process = netapi.Process{Path: "/opt/app/bin/app", Pid: 9}
			ctx, destination := processScopeContext(t, nil)
			if _, _, err := router.ResolveTCP(ctx, destination, contractroute.Target{}); err != nil {
				t.Fatal(err)
			}
			if id, _ := ctx.MatchedRule(); id != tc.wantRule || (host.calls > 0) != tc.lookup {
				t.Fatalf("rule=%q lookups=%d, want %q lookup=%v", id, host.calls, tc.wantRule, tc.lookup)
			}
			if !tc.lookup {
				return
			}
			// The connection keeps the path exactly as the OS reported it,
			// and the history names the glob rule.
			if path, _, _ := ctx.GetProcess(); path != "/opt/app/bin/app" {
				t.Fatalf("recorded path = %q", path)
			}
			if history := ctx.MatchHistory(); len(history) == 0 || history[0].RuleName != "apps-rule" {
				t.Fatalf("history = %#v", history)
			}
		})
	}
}

func TestProcessSearchDuringUpdates(t *testing.T) {
	m := newTestMatchers(t)
	book := newProcessListBook(localProcessList("a", "/opt/a/**"))
	m.list.lists = book
	rules := []contractroute.RouteRule{processRule("a-rule", "a", "direct"), alwaysRule("fallback", "proxy", contractroute.Target{})}
	if err := m.Update(rules...); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			for !stop.Load() {
				// Each generation matches exactly one of these; never both
				// and never a half-built index.
				got := searchLists(m, "/opt/a/bin/x")
				other := searchLists(m, "/opt/b/bin/x")
				if len(got) > 1 || len(other) > 1 {
					errs <- errors.New("duplicate list IDs")
					return
				}
				ctx, addr := processMatchContext(t, "/opt/a/bin/x")
				if mode := m.Match(ctx, addr); mode.Mode() != ModeDirect && mode.Mode() != ModeProxy {
					errs <- errors.New("unexpected mode " + mode.Mode().String())
					return
				}
			}
		})
	}
	for i := range 200 {
		if i%2 == 0 {
			book.set(localProcessList("a", "/opt/b/**", "/opt/b/bin/x"))
		} else {
			book.set(localProcessList("a", "/opt/a/**", "**/a/**"))
		}
		if err := m.Update(rules...); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// TestProcessGlobsSurviveSaveApplyAndRestart stores a glob list in SQLite,
// activates it, then starts a second runtime from the same database.
func TestProcessGlobsSurviveSaveApplyAndRestart(t *testing.T) {
	old := configuration.DataDir.Load()
	configuration.DataDir.Store(t.TempDir())
	t.Cleanup(func() { configuration.DataDir.Store(old) })
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	listStore := plainstore.NewRouteListStore(db.DB())
	ruleStore := plainstore.NewRouteRuleStore(db.DB())
	settings := plainstore.NewRouteSettingsStore(db.DB())
	if err := listStore.SaveRouteList(t.Context(), localProcessList("editor", "/Applications/ExampleEditor.app/**", "**/aaa/**"), 0); err != nil {
		t.Fatal(err)
	}
	if err := ruleStore.SaveRule(t.Context(), processRule("editor-rule", "editor", "block"), 0, 0); err != nil {
		t.Fatal(err)
	}
	start := func() *Rules {
		lists := NewLists(listStore, settings, t.TempDir())
		t.Cleanup(func() { _ = lists.Close() })
		rules := NewRules(ruleStore, settings, NewRoute(nil, staticResolverBook{resolver: staticResolver{}}, lists, nil))
		t.Cleanup(func() { _ = rules.Close() })
		return rules
	}
	check := func(rules *Rules) {
		t.Helper()
		for path, want := range map[string]string{
			"/Applications/ExampleEditor.app/Contents/Frameworks/Example GPU.app/Contents/MacOS/Example GPU": "editor-rule",
			"/usr/local/aaa/lib/app": "editor-rule",
			"/opt/aaab/bin/app":      "",
		} {
			if got := matchedRule(t, rules.route.ms, path); got != want {
				t.Errorf("%q matched %q, want %q", path, got, want)
			}
		}
	}
	first := start()
	check(first)
	if err := first.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	check(first)
	check(start())
}

// TestWindowsProcessRules compiles lists with Windows path syntax, whatever
// the host, and checks drive, case, UNC and extended-length handling end to
// end through rule matching.
func TestWindowsProcessRules(t *testing.T) {
	useProcessFlavor(t, processpath.Windows)
	m := newTestMatchers(t)
	m.list.lists = newProcessListBook(
		localProcessList("c-drive", `C:\Program Files\ExampleEditor\**`),
		localProcessList("any-drive", `**/Program Files/ExampleTool/**`),
		localProcessList("system", `C:\Windows\System32\svchost.exe`, ":System", "/usr/bin/curl"),
	)
	if err := m.Update(processRule("c-rule", "c-drive", "direct"), processRule("any-rule", "any-drive", "direct"),
		processRule("system-rule", "system", "direct"), alwaysRule("fallback", "proxy", contractroute.Target{})); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		`C:\Program Files\ExampleEditor\bin.exe`:         "c-rule",
		`c:\program files\exampleeditor\bin.exe`:         "c-rule",
		`\\?\C:\Program Files\ExampleEditor\bin.exe`:     "c-rule",
		`D:\Program Files\ExampleEditor\bin.exe`:         "fallback",
		`C:\Program Files\ExampleEditor-old\bin.exe`:     "fallback",
		`D:\Program Files\ExampleTool\tool.exe`:          "any-rule",
		`\\server\share\Program Files\ExampleTool\t.exe`: "any-rule",
		`c:\windows\system32\SVCHOST.EXE`:                "system-rule",
		":System":                                        "system-rule",
		"/usr/bin/curl":                                  "fallback", // a Unix entry is inert on Windows
	} {
		if got := matchedRule(t, m, path); got != want {
			t.Errorf("%q matched %q, want %q", path, got, want)
		}
	}
	if len(m.listIssues) != 0 {
		t.Fatalf("issues = %+v", m.listIssues)
	}
}

// fileURL is a file URL the downloader accepts on every platform:
// file:///tmp/x on Unix, file:///D:/x on Windows.
func fileURL(path string) string {
	return "file:///" + strings.TrimPrefix(filepath.ToSlash(path), "/")
}
