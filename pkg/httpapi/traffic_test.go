package httpapi

import (
	"context"
	json "encoding/json/v2"
	"net/http/httptest"
	"strings"
	"testing"

	schemaapi "github.com/Asutorufa/yuhaiin/pkg/schema/api"
)

type trafficStub struct {
	total  *schemaapi.TrafficTotals
	events <-chan schemaapi.TrafficEvent
	err    error
}

func (t trafficStub) Totals(context.Context) (*schemaapi.TrafficTotals, error) { return t.total, t.err }
func (t trafficStub) Watch(context.Context) (<-chan schemaapi.TrafficEvent, error) {
	return t.events, t.err
}

func TestTrafficTotals(t *testing.T) {
	handler := TrafficTotals(trafficStub{
		total: &schemaapi.TrafficTotals{
			Download: 3,
			Upload:   2,
			Counters: map[uint64]schemaapi.Counter{
				1: {Download: 1, Upload: 1},
			},
		},
	})

	req := httptest.NewRequest("GET", "/api/v1/connections/total", nil)
	rec := httptest.NewRecorder()

	if err := handler(rec, req); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != 200 {
		t.Fatalf("unexpected status: %d", rec.Code)
	}

	var got schemaapi.TrafficTotals
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}

	if got.Download != 3 || got.Upload != 2 {
		t.Fatalf("unexpected totals: %+v", got)
	}
	if got.Counters[1].Download != 1 || got.Counters[1].Upload != 1 {
		t.Fatalf("unexpected counters: %+v", got.Counters)
	}
}

func TestTrafficEvents(t *testing.T) {
	ch := make(chan schemaapi.TrafficEvent, 1)
	ch <- schemaapi.TrafficEvent{
		Type:    "connections_added",
		Payload: []byte(`{"connections":[]}`),
	}
	close(ch)

	handler := TrafficEvents(trafficStub{events: ch})
	req := httptest.NewRequest("GET", "/api/v1/connections/events", nil)
	rec := httptest.NewRecorder()

	if err := handler(rec, req); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != 200 {
		t.Fatalf("unexpected status: %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "event: connections_added") {
		t.Fatalf("event name is missing: %q", body)
	}
	if !strings.Contains(body, `data: {"connections":[]}`) {
		t.Fatalf("event payload is missing: %q", body)
	}
}
