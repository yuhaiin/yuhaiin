package auth

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
)

type fakeLogTools struct {
	httpapi.ToolsController
	mu      sync.Mutex
	queries []contracttools.LogQuery
}

func (f *fakeLogTools) RecentLogs(_ context.Context, query contracttools.LogQuery) (contracttools.RecentLogs, error) {
	f.mu.Lock()
	f.queries = append(f.queries, query)
	f.mu.Unlock()
	return contracttools.RecentLogs{Lines: []string{"level=ERROR msg=\"dial failed\" host=example.com"}}, nil
}

type fakeProfiler struct {
	mu      sync.Mutex
	started []contracttools.ProfileRequest
	removed []string
}

func (f *fakeProfiler) Sessions(context.Context) (contracttools.ProfileSessions, error) {
	return contracttools.ProfileSessions{Enabled: true, Sessions: []contracttools.ProfileSession{}}, nil
}
func (f *fakeProfiler) StartProfile(_ context.Context, request contracttools.ProfileRequest) (contracttools.ProfileSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, request)
	return contracttools.ProfileSession{ID: "session-1", Type: request.Type, Seconds: request.Seconds, Status: "running"}, nil
}
func (f *fakeProfiler) RemoveProfile(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, id)
	return nil
}
func (f *fakeProfiler) AnalyzeProfile(_ context.Context, request contracttools.ProfileAnalysisRequest) (contracttools.ProfileAnalysis, error) {
	return contracttools.ProfileAnalysis{Session: contracttools.ProfileSession{ID: request.ID, Status: "completed"}, SampleType: "cpu", Unit: "nanoseconds", Total: 100,
		Functions: []contracttools.ProfileFunction{{Function: "example/hot.Path", Flat: 70, FlatPercent: 70, Cumulative: 90, CumulativePercent: 90}}}, nil
}

type fakeConnections struct {
	httpapi.ConnectionMonitor
	mu       sync.Mutex
	from, to time.Time
}

func (f *fakeConnections) Telemetry(_ context.Context, from, to time.Time, _ int) (contractconnection.TelemetrySummary, error) {
	f.mu.Lock()
	f.from, f.to = from, to
	f.mu.Unlock()
	return contractconnection.TelemetrySummary{}, nil
}
func (f *fakeConnections) FailedHistory(context.Context) (contractconnection.FailedHistoryList, error) {
	items := make([]contractconnection.FailedHistory, 120)
	for i := range items {
		items[i] = contractconnection.FailedHistory{Host: "failed.example", Error: "timeout"}
	}
	return contractconnection.FailedHistoryList{Items: items}, nil
}

type diagnosticsFixture struct {
	*mcpTest
	logs        *fakeLogTools
	profiler    *fakeProfiler
	connections *fakeConnections
}

func newDiagnosticsFixture(t *testing.T) *diagnosticsFixture {
	f := &diagnosticsFixture{logs: &fakeLogTools{}, profiler: &fakeProfiler{}, connections: &fakeConnections{}}
	f.mcpTest = newMCPTestWith(t, httpapi.V2Services{Tools: f.logs, Profiler: f.profiler, Connections: f.connections})
	return f
}

func (f *diagnosticsFixture) retrievals() int {
	var n int
	if err := f.runtime.store.db.QueryRowContext(f.t.Context(), `SELECT count(*) FROM management_security_events WHERE event='secret.retrieval_authorized' AND subject_id='logs.recent'`).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestMCPDiagnosticToolsAnalyzePerformance(t *testing.T) {
	f := newDiagnosticsFixture(t)
	access, _ := f.authorize(f.admin, "mcp:connect diagnostics:run metrics:read connections:read")
	session, err := f.connect(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	names := toolNames(t, session)
	for _, want := range []string{"capture_profile", "analyze_profile", "list_profiles", "delete_profile", "get_runtime_stats", "run_diagnostics", "get_traffic_telemetry", "get_failed_connections"} {
		if !slices.Contains(names, want) {
			t.Errorf("missing %s in %v", want, names)
		}
	}
	if slices.Contains(names, "get_logs") {
		t.Fatal("get_logs listed without secrets:read")
	}
	if _, isError, err := callText(t, session, "get_logs", map[string]any{}); err == nil && !isError {
		t.Fatal("get_logs ran without secrets:read")
	}

	stats := call(t, session, "get_runtime_stats", map[string]any{})
	if stats["goroutines"].(float64) < 1 || stats["goVersion"] == "" {
		t.Fatalf("stats = %v", stats)
	}

	// One call starts, waits for and summarizes a profile, then discards it.
	analysis := call(t, session, "capture_profile", map[string]any{"type": "cpu", "mode": "functions", "limit": 5})
	if functions := analysis["functions"].([]any); len(functions) != 1 || functions[0].(map[string]any)["function"] != "example/hot.Path" {
		t.Fatalf("analysis = %v", analysis)
	}
	if len(f.profiler.started) != 1 || f.profiler.started[0] != (contracttools.ProfileRequest{Type: "cpu", Seconds: 10}) || !slices.Equal(f.profiler.removed, []string{"session-1"}) {
		t.Fatalf("profiler calls: started %v removed %v", f.profiler.started, f.profiler.removed)
	}
	call(t, session, "capture_profile", map[string]any{"type": "heap", "keep": true})
	if len(f.profiler.removed) != 1 {
		t.Fatal("a kept profile was deleted")
	}
	if _, isError, _ := callText(t, session, "capture_profile", map[string]any{"type": "threadcreate"}); !isError {
		t.Fatal("unsupported profile type accepted")
	}

	call(t, session, "get_traffic_telemetry", map[string]any{"minutes": 30})
	if span := f.connections.to.Sub(f.connections.from); span < 30*time.Minute || span > 32*time.Minute {
		t.Fatalf("telemetry window = %v", span)
	}
	failed := call(t, session, "get_failed_connections", map[string]any{"limit": 10})
	if len(failed["items"].([]any)) != 10 || failed["total"] != float64(120) || failed["truncated"] != true {
		t.Fatalf("failed = total %v truncated %v", failed["total"], failed["truncated"])
	}
}

// Logs are raw secret data: MCP clients need an explicit secrets:read grant,
// only the MCP resource can grant it, and every read is audited.
func TestMCPLogsRequireAuditedSecretRead(t *testing.T) {
	f := newDiagnosticsFixture(t)
	access, _ := f.authorize(f.admin, "mcp:connect diagnostics:run secrets:read")
	session, err := f.connect(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if !slices.Contains(toolNames(t, session), "get_logs") {
		t.Fatal("get_logs not listed with secrets:read")
	}
	logs := call(t, session, "get_logs", map[string]any{"level": "error", "contains": "dial", "limit": 20})
	if lines := logs["lines"].([]any); len(lines) != 1 || !strings.Contains(lines[0].(string), "dial failed") {
		t.Fatalf("logs = %v", logs)
	}
	if f.logs.queries[0] != (contracttools.LogQuery{Limit: 20, Level: "error", Contains: "dial"}) {
		t.Fatalf("query = %+v", f.logs.queries[0])
	}
	if f.retrievals() != 1 {
		t.Fatal("log read was not audited")
	}

	// Losing secrets:read stops the next read even with an existing grant.
	reader := testUser(t, f.runtime.store, "diagnoser", Admin)
	readerAccess, _ := f.authorize(reader, "mcp:connect diagnostics:run secrets:read")
	readerSession, err := f.connect(t.Context(), readerAccess)
	if err != nil {
		t.Fatal(err)
	}
	defer readerSession.Close()
	role, err := f.runtime.store.SaveRole(t.Context(), principal(f.admin), Role{Name: "Diagnostics", Permissions: []Permission{MCPConnect, Diagnostics}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.runtime.store.UpdateUser(t.Context(), f.admin.ID, reader.ID, reader.Login, NoManagement, false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.runtime.store.AssignRoles(t.Context(), principal(f.admin), reader.ID, 0, []string{role.ID}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := callText(t, readerSession, "get_logs", map[string]any{}); err == nil {
		t.Fatal("logs read after secrets:read was withdrawn")
	}
	if f.retrievals() != 1 {
		t.Fatal("a denied log read was audited as authorized")
	}

	// The management API resource never offers secrets:read.
	values := authorizeValues(f.client, "", "secrets:read")
	values.Set("redirect_uri", "http://127.0.0.1/callback")
	values.Set("resource", f.url+"/api")
	if _, err := f.runtime.Authorization.StartAuthorization(t.Context(), values); err == nil {
		t.Fatal("secrets:read offered for the management API")
	}
	if slices.Contains(ManagementAPIResource().Scopes, SecretsRead) {
		t.Fatal("management API resource exposes secrets:read")
	}
}

// The new operations are also HTTP API routes behind the same rules.
func TestDiagnosticOperationsOverHTTP(t *testing.T) {
	f := newDiagnosticsFixture(t)
	admin, err := f.runtime.store.IssueToken(t.Context(), principal(f.admin), f.admin.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	reader := testUser(t, f.runtime.store, "reader", ReadOnly)
	readerToken, _ := f.runtime.store.IssueToken(t.Context(), principal(f.admin), reader.ID, nil, 0)
	post := func(token, operation string) int {
		request, _ := http.NewRequest(http.MethodPost, f.url+"/api/v2/rpc/"+operation, strings.NewReader(`{}`))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Logf("%s: %d %s", operation, response.StatusCode, body)
		}
		return response.StatusCode
	}
	if status := post(admin.Secret, "logs.recent"); status != 200 || f.retrievals() != 1 {
		t.Fatalf("admin logs = %d, audits %d", status, f.retrievals())
	}
	if status := post(readerToken.Secret, "logs.recent"); status != 403 {
		t.Fatalf("read-only logs = %d", status)
	}
	if status := post(readerToken.Secret, "runtime.stats"); status != 200 {
		t.Fatalf("read-only runtime stats = %d", status)
	}
	if status := post(readerToken.Secret, "profiler.start"); status != 403 {
		t.Fatalf("read-only profiler = %d", status)
	}
}
