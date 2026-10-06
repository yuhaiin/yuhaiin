package yuhaiin

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/app"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
)

type statusNodes struct{ httpapi.NodeController }

func (statusNodes) Selected(context.Context) (contractnode.Selection, error) {
	return contractnode.Selection{
		TCP: &contractnode.Node{ID: "tcp-node", Name: "TCP exit", Chain: []contractnode.Protocol{{Type: "shadowsocks", Shadowsocks: &contractnode.Shadowsocks{Password: "secret-password"}}}},
		UDP: &contractnode.Node{ID: "udp-node", Name: "UDP exit"},
	}, nil
}
func (statusNodes) Latency(_ context.Context, id string, request contractnode.LatencyRequest) (contractnode.LatencyResponse, error) {
	if id == "tcp-node" && request.Type == "http" {
		return contractnode.LatencyResponse{OK: true, LatencyMS: 12}, nil
	}
	if id == "udp-node" && request.Type == "udp" {
		return contractnode.LatencyResponse{}, errors.New("UDP unreachable")
	}
	return contractnode.LatencyResponse{}, errors.New("incorrect probe")
}

func TestNativeStatusAndHealthContract(t *testing.T) {
	a := &App{instance: &app.AppInstance{Node: statusNodes{}}, startedAt: time.Now().Add(-time.Minute)}
	a.started.Store(true)
	snapshot, err := a.NativeStatus()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(snapshot, "secret-password") || strings.Contains(snapshot, "chain") {
		t.Fatal("native display exposed node credentials")
	}
	var status nativeStatus
	if err := json.Unmarshal([]byte(snapshot), &status); err != nil {
		t.Fatal(err)
	}
	if status.TCP.ID != "tcp-node" || status.UDP.ID != "udp-node" || status.DurationSeconds < 60 {
		t.Fatalf("status: %+v", status)
	}
	data, err := a.CheckHealth()
	if err != nil {
		t.Fatal(err)
	}
	var health nativeHealth
	if err := json.Unmarshal([]byte(data), &health); err != nil {
		t.Fatal(err)
	}
	if !health.TCP.OK || health.TCP.LatencyMS != 12 || health.UDP.OK || health.UDP.Error != "UDP unreachable" {
		t.Fatalf("health: %+v", health)
	}
	a.started.Store(false)
	if _, err := a.NativeStatus(); err == nil {
		t.Fatal("status succeeded after stop")
	}
	if _, err := a.CheckHealth(); err == nil {
		t.Fatal("probe succeeded after stop")
	}
}
