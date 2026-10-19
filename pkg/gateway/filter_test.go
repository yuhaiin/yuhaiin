package gateway

import (
	"net/http/httptest"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
)

func TestURLFilterSubsetAndErrorStatistics(t *testing.T) {
	filter, err := CompileFilters([]contract.FilterList{{ID: "ads", Enabled: true, Text: "[Adblock Plus 2.0]\n! comment\n||example.com/ads/*\n@@||example.com/ads/allowed|\n||tracker.example^\nexample##.banner\n||bad.example$script\n/unsupported-regex/"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(filter.reports) != 1 || filter.reports[0].Accepted != 3 || filter.reports[0].Rejected != 3 || len(filter.reports[0].Errors) != 3 {
		t.Fatalf("report=%+v", filter.reports)
	}
	for _, test := range []struct {
		url     string
		blocked bool
	}{{"https://example.com/ads/banner.js", true}, {"http://sub.example.com/ads/banner.js", true}, {"https://example.com/ads/allowed", false}, {"https://badexample.com/ads/banner.js", false}, {"https://tracker.example/anything", true}, {"https://example.com/content", false}} {
		if got := filter.blocked(httptest.NewRequest("GET", test.url, nil)); got != test.blocked {
			t.Errorf("url=%s blocked=%v", test.url, got)
		}
	}
}

func TestUpstreamBalancingAndLimits(t *testing.T) {
	u, err := compileUpstream(contract.Upstream{ID: "u", Balance: "weighted_round_robin", MaxConcurrent: 1, Backends: []contract.Backend{{URL: "http://a.example", Weight: 1}, {URL: "http://b.example", Weight: 3}}})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for range 40 {
		b, err := u.pick()
		if err != nil {
			t.Fatal(err)
		}
		counts[b.url.Host]++
		u.finish(b, false)
	}
	if counts["a.example"] != 10 || counts["b.example"] != 30 {
		t.Fatalf("distribution=%v", counts)
	}
	release, err := u.acquire()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.acquire(); err == nil {
		t.Fatal("maximum concurrent requests exceeded")
	}
	release()
	b := u.backends[0]
	for range 3 {
		u.recordHealth(b, true)
	}
	if b.unavailableUntil.Load() == 0 {
		t.Fatal("passive failure did not quarantine backend")
	}
	for range 4 {
		chosen, err := u.pick()
		if err != nil {
			t.Fatal(err)
		}
		if chosen == b {
			t.Fatal("selected quarantined backend")
		}
		u.finish(chosen, false)
	}
	u.recordHealth(b, false)
	if b.unavailableUntil.Load() != 0 {
		t.Fatal("healthy backend did not recover")
	}
}
