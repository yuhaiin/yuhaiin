package httpapi

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

type trafficControlAPIStub struct {
	InboundStore
	current trafficcontrol.Config
}

func (s *trafficControlAPIStub) TrafficControl(context.Context) (trafficcontrol.Config, error) {
	return s.current, nil
}
func (s *trafficControlAPIStub) SaveTrafficControl(_ context.Context, c trafficcontrol.Config) error {
	if err := trafficcontrol.NewManager().Apply(c); err != nil {
		return err
	}
	s.current = c
	return nil
}

func TestTrafficControlRPCGetPut(t *testing.T) {
	stub := &trafficControlAPIStub{}
	api := v2API{services: V2Services{Inbounds: stub}}
	c := trafficcontrol.Config{Enabled: true, Profiles: map[string]trafficcontrol.Profile{"bulk": {
		Upload: trafficcontrol.Rate{BytesPerSecond: 1024, BurstBytes: 128},
	}}, InboundProfiles: map[string]string{"mixed": "bulk"}}
	if _, err := api.saveTrafficControl(t.Context(), &c); err != nil {
		t.Fatal(err)
	}
	got, err := api.trafficControl(t.Context(), &emptyRequest{})
	if err != nil || !got.Enabled || got.InboundProfiles["mixed"] != "bulk" {
		t.Fatalf("get/put: %+v %v", got, err)
	}
	bad := trafficcontrol.Config{Enabled: true, DefaultProfile: "missing"}
	if _, err = api.saveTrafficControl(t.Context(), &bad); err == nil {
		t.Fatal("invalid profile accepted")
	}
	got, _ = api.trafficControl(t.Context(), &emptyRequest{})
	if !got.Enabled || got.InboundProfiles["mixed"] != "bulk" {
		t.Fatal("invalid profile replaced persisted runtime")
	}
}
