package httpapi

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

type trafficControlStatusStub struct{ InboundStore }

func (trafficControlStatusStub) TrafficControlStatus() trafficcontrol.Status {
	return trafficcontrol.Status{
		Global: trafficcontrol.Counters{Sessions: 10, QueueBytes: 1024, DeniedSessions: 3},
		NAT:    trafficcontrol.Counters{Sessions: 4, DeniedPackets: 7},
		InboundScopes: []trafficcontrol.ScopeStatus{
			{ID: "mixed", Counters: trafficcontrol.Counters{Sessions: 2}},
		},
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
