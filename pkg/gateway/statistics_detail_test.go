package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
)

func TestDetailStatisticsBreakdowns(t *testing.T) {
	rules := []contract.Rule{
		{ID: "ads", Enabled: true, Priority: 1, Match: contract.Condition{Field: "path", Operator: "prefix", Value: "/ads"}, Action: contract.Action{Type: "block", Status: 204}},
		{ID: "hello", Enabled: true, Priority: 2, Match: contract.Condition{Field: "path", Value: "/hello"}, Action: contract.Action{Type: "respond", Body: "hello"}},
	}
	e, err := NewEngine(contract.Gateway{ID: "g", Default: contract.Action{Type: "respond", Status: 404}}, rules, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	for _, target := range []string{"http://a.example/ads/1", "http://a.example/ads/2", "http://b.example/hello", "http://c.example/missing"} {
		e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, target, nil))
	}
	got := e.Counters.detail.snapshot("g", []string{"ads", "hello"}, 0, time.Now())
	if got.StatusClasses[2] != 3 || got.StatusClasses[4] != 1 {
		t.Fatalf("status classes = %v", got.StatusClasses)
	}
	if got.Rules[0].Hits != 2 || got.Rules[1].Hits != 1 || got.DefaultHits != 1 {
		t.Fatalf("rule hits = %+v default=%d", got.Rules, got.DefaultHits)
	}
	if got.TopHosts[0].Host != "a.example" || got.TopHosts[0].Requests != 2 || got.TopHosts[0].Blocked != 2 {
		t.Fatalf("top hosts = %+v", got.TopHosts)
	}
	if got.BytesOut != uint64(len("hello")) {
		t.Fatalf("bytes out = %d", got.BytesOut)
	}
	last := len(got.History.Requests) - 1
	if got.History.Requests[last] != 4 || got.History.Blocked[last] != 2 {
		t.Fatalf("history tail = %d/%d", got.History.Requests[last], got.History.Blocked[last])
	}
	var latency uint64
	for _, b := range got.Latency {
		latency += b.Count
	}
	if latency != 4 || got.SinceUnixMS == 0 {
		t.Fatalf("latency total=%d since=%d", latency, got.SinceUnixMS)
	}
	e.Counters.detail.reset(time.Now())
	if after := e.Counters.detail.snapshot("g", []string{"ads"}, 0, time.Now()); after.Rules[0].Hits != 0 || len(after.TopHosts) != 0 {
		t.Fatalf("reset kept %+v", after)
	}
}

func TestTopHostsStayBounded(t *testing.T) {
	var d detailStatistics
	for i := range topHostCapacity * 3 {
		d.countHostLocked(string(rune('a'+i%26))+string(rune('A'+i/26)), false)
	}
	for range 50 {
		d.countHostLocked("heavy.example", true)
	}
	if len(d.hosts) > topHostCapacity {
		t.Fatalf("hosts = %d", len(d.hosts))
	}
	got := d.snapshot("g", nil, 0, time.Now())
	if got.TopHosts[0].Host != "heavy.example" || got.TopHosts[0].Blocked != 50 {
		t.Fatalf("top = %+v", got.TopHosts[0])
	}
}

func TestDetailStatisticsCountsProxiedBytesAndImplicitStatus(t *testing.T) {
	e, _ := testEngine(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(append([]byte("echo:"), body...))
	}))
	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "http://site.example/", strings.NewReader("payload")))
	if w.Body.String() != "echo:payload" {
		t.Fatalf("body = %q", w.Body.String())
	}
	got := e.Counters.detail.snapshot("g", nil, 0, time.Now())
	if got.BytesIn != 7 || got.BytesOut != 12 || got.StatusClasses[2] != 1 {
		t.Fatalf("bytes in=%d out=%d status=%v", got.BytesIn, got.BytesOut, got.StatusClasses)
	}
	if last := len(got.History.Forwarded) - 1; got.History.Forwarded[last] != 1 {
		t.Fatalf("forwarded history = %d", got.History.Forwarded[last])
	}
}
