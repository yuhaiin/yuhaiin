package yuhaiin

import (
	"context"
	"encoding/json/v2"
	"errors"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

type nativeNode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type nativeStatus struct {
	StartedAt       int64                             `json:"startedAt"`
	DurationSeconds int64                             `json:"durationSeconds"`
	TCP             *nativeNode                       `json:"tcp,omitzero"`
	UDP             *nativeNode                       `json:"udp,omitzero"`
	Session         contractconnection.SessionSummary `json:"session"`
}

func nativeSelected(node *contractnode.Node) *nativeNode {
	if node == nil {
		return nil
	}
	return &nativeNode{ID: node.ID, Name: node.Name}
}

// NativeStatus exposes only display data: node credentials and chains never
// cross Binder. Session counters come directly from the existing flow collector.
func (a *App) NativeStatus() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.started.Load() || a.instance == nil {
		return "", errors.New("core is not running")
	}
	selected, err := a.instance.Node.Selected(context.Background())
	if err != nil {
		return "", err
	}
	snapshot := nativeStatus{StartedAt: a.startedAt.UnixMilli(), DurationSeconds: int64(time.Since(a.startedAt) / time.Second), TCP: nativeSelected(selected.TCP), UDP: nativeSelected(selected.UDP)}
	if monitor, ok := a.instance.Connections.(interface {
		SessionSummary() contractconnection.SessionSummary
	}); ok {
		snapshot.Session = monitor.SessionSummary()
	}
	data, err := json.Marshal(snapshot)
	return string(data), err
}

type nativeNodeHealth struct {
	ID        string `json:"id"`
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latencyMs"`
	Error     string `json:"error"`
}

type nativeHealth struct {
	CheckedAt int64             `json:"checkedAt"`
	TCP       *nativeNodeHealth `json:"tcp,omitzero"`
	UDP       *nativeNodeHealth `json:"udp,omitzero"`
}

// CheckHealth reuses the node latency probes (HTTP for TCP, DNS for UDP).
// It is bounded by the existing probe timeout and runs outside the lifecycle
// lock so stopping the VPN does not wait for a network request to finish.
func (a *App) CheckHealth() (string, error) {
	a.mu.Lock()
	instance := a.instance
	running := a.started.Load()
	a.mu.Unlock()
	if !running || instance == nil {
		return "", errors.New("core is not running")
	}
	ctx := context.Background()
	selected, err := instance.Node.Selected(ctx)
	if err != nil {
		return "", err
	}
	check := func(node *contractnode.Node, kind string) *nativeNodeHealth {
		if node == nil {
			return nil
		}
		result, err := instance.Node.Latency(ctx, node.ID, contractnode.LatencyRequest{Type: kind})
		health := &nativeNodeHealth{ID: node.ID, OK: result.OK, LatencyMS: result.LatencyMS, Error: result.Error}
		if err != nil {
			health.OK = false
			health.Error = err.Error()
		}
		return health
	}
	// The two probes are independent and the snapshot publishes both together.
	tcp := make(chan *nativeNodeHealth, 1)
	go func() { tcp <- check(selected.TCP, "http") }()
	udp := check(selected.UDP, "udp")
	health := nativeHealth{CheckedAt: time.Now().UnixMilli(), TCP: <-tcp, UDP: udp}
	data, err := json.Marshal(health)
	return string(data), err
}
