package gateway

import (
	"net/http/httptest"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/prometheus/client_golang/prometheus"
)

func TestGatewayMetricsUseExistingCounters(t *testing.T) {
	m, _ := newTestManager(t, contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "Metrics", Enabled: true, Default: contract.Action{Type: "block", Status: 204}}}}, nil)
	g := m.current.Load().gateways["g"].engine
	g.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://example.com/ads/banner", nil))
	registry := prometheus.NewRegistry()
	registry.MustRegister(m.Metrics())
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, family := range families {
		if family.GetName() == "yuhaiin_gateway_blocked_total" {
			found = true
			if family.Metric[0].Counter.GetValue() != 1 {
				t.Fatal("request counter was not exported")
			}
		}
	}
	if !found {
		t.Fatal("missing Gateway metrics")
	}
}
