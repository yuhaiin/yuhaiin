package httpapi

import (
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

type trafficControlStatusStub struct {
	InboundStore
	queues []trafficcontrol.QueueStatus
}

func (s trafficControlStatusStub) TrafficControlStatus() trafficcontrol.Status {
	return trafficcontrol.Status{
		Queues: s.queues,
		Global: trafficcontrol.Counters{Sessions: 10, QueueBytes: 1024, DeniedSessions: 3},
		NAT:    trafficcontrol.Counters{Sessions: 4, DeniedPackets: 7},
		InboundScopes: []trafficcontrol.ScopeStatus{
			{ID: "mixed", Counters: trafficcontrol.Counters{Sessions: 2}},
		},
	}
}

func TestTrafficControlStatusRPCEncodesQueueSojourn(t *testing.T) {
	for _, sojourn := range []time.Duration{0, 5*time.Millisecond + 123*time.Nanosecond} {
		t.Run(sojourn.String(), func(t *testing.T) {
			mux := http.NewServeMux()
			RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
				mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
					if err := handler(w, r); err != nil {
						t.Errorf("handler: %v", err)
					}
				})
			}, V2Services{Inbounds: trafficControlStatusStub{queues: []trafficcontrol.QueueStatus{
				{ID: "test", Counters: trafficcontrol.FairStats{MaxSojourn: int64(sojourn)}},
			}}})
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v2/rpc/traffic_control.status", strings.NewReader("{}")))
			if response.Code != http.StatusOK {
				t.Fatalf("status: %d %s", response.Code, response.Body.String())
			}
			var got struct {
				Queues []struct {
					ID       string                     `json:"id"`
					Counters struct{ MaxSojourn int64 } `json:"counters"`
				} `json:"queues"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if len(got.Queues) != 1 || got.Queues[0].ID != "test" || got.Queues[0].Counters.MaxSojourn != int64(sojourn) {
				t.Fatalf("queue sojourn must be a number in nanoseconds: %+v", got)
			}
		})
	}
}

func TestTrafficControlStatusRPC(t *testing.T) {
	api := v2API{services: V2Services{Inbounds: trafficControlStatusStub{}}}
	got, err := api.trafficControlStatus(context.Background(), &emptyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Global.Sessions != 10 || got.NAT.DeniedPackets != 7 || len(got.InboundScopes) != 1 || got.InboundScopes[0].ID != "mixed" {
		t.Fatalf("invalid traffic control diagnostics: %+v", got)
	}
	api.services.Inbounds = nil
	if _, err = api.trafficControlStatus(context.Background(), &emptyRequest{}); err == nil {
		t.Fatal("missing backend reported healthy")
	}
}
