package statistics

import (
	"context"
	"errors"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	"github.com/Asutorufa/yuhaiin/pkg/control"
)

type ConnectionMonitor struct {
	connections *Connections
}

func NewConnectionMonitor(connections *Connections) ConnectionMonitor {
	return ConnectionMonitor{connections: connections}
}

func (m ConnectionMonitor) Total(ctx context.Context) (contractconnection.TotalFlow, error) {
	if m.connections == nil {
		return contractconnection.TotalFlow{}, errors.New("connections controller is unavailable")
	}
	return m.connections.Total(ctx)
}

// FlowTotals reads only the two totals used by the Android speed notification.
// It avoids allocating and copying a counter entry for every active flow.
func (m ConnectionMonitor) FlowTotals() (download, upload uint64) {
	if m.connections == nil || m.connections.Cache == nil {
		return 0, 0
	}
	return m.connections.Cache.LoadDownload(), m.connections.Cache.LoadUpload()
}

func (m ConnectionMonitor) Traffic(ctx context.Context, interval string, from, to time.Time) (contractconnection.TrafficSeries, error) {
	if m.connections == nil {
		return contractconnection.TrafficSeries{}, errors.New("connections controller is unavailable")
	}
	return m.connections.Traffic(ctx, interval, from, to)
}

func (m ConnectionMonitor) Telemetry(ctx context.Context, from, to time.Time, limit int) (contractconnection.TelemetrySummary, error) {
	if m.connections == nil {
		return contractconnection.TelemetrySummary{}, errors.New("connections controller is unavailable")
	}
	return m.connections.Telemetry(ctx, from, to, limit)
}

func (m ConnectionMonitor) List(ctx context.Context) (contractconnection.Connections, error) {
	if m.connections == nil {
		return contractconnection.Connections{}, errors.New("connections controller is unavailable")
	}
	return m.connections.Conns(ctx)
}

func (m ConnectionMonitor) Close(ctx context.Context, ids []uint64) error {
	if m.connections == nil {
		return errors.New("connections controller is unavailable")
	}
	return m.connections.CloseConn(ctx, ids)
}

func (m ConnectionMonitor) FailedHistory(ctx context.Context) (contractconnection.FailedHistoryList, error) {
	if m.connections == nil {
		return contractconnection.FailedHistoryList{}, errors.New("connections controller is unavailable")
	}
	return m.connections.FailedHistory(ctx)
}

func (m ConnectionMonitor) AllHistory(ctx context.Context) (contractconnection.AllHistoryList, error) {
	if m.connections == nil {
		return contractconnection.AllHistoryList{}, errors.New("connections controller is unavailable")
	}
	return m.connections.AllHistory(ctx)
}

func (m ConnectionMonitor) Events(ctx context.Context, send func(contractconnection.Event) error) error {
	if m.connections == nil {
		return errors.New("connections controller is unavailable")
	}
	return m.connections.Notify(contractNotifyStream{ctx: ctx, send: send})
}

type contractNotifyStream struct {
	ctx  context.Context
	send func(contractconnection.Event) error
}

func (s contractNotifyStream) Send(data *contractconnection.Event) error {
	if data == nil {
		return s.send(contractconnection.Event{Type: "empty"})
	}
	return s.send(*data)
}

func (s contractNotifyStream) Context() context.Context { return s.ctx }

var _ control.ServerStream[contractconnection.Event] = contractNotifyStream{}

// SessionSummary does not allocate the per-flow counter map or connection details.
func (m ConnectionMonitor) SessionSummary() contractconnection.SessionSummary {
	c := m.connections
	if c == nil || c.Cache == nil {
		return contractconnection.SessionSummary{}
	}
	active := 0
	c.connStore.Range(func(_ uint64, _ connection) bool { active++; return true })
	return contractconnection.SessionSummary{
		Download: formatUint64(c.Cache.LoadRunningDownload()), Upload: formatUint64(c.Cache.LoadRunningUpload()),
		TotalDownload: formatUint64(c.Cache.LoadDownload()), TotalUpload: formatUint64(c.Cache.LoadUpload()),
		Active: active, Opened: formatUint64(c.openedConnections.Load()), Failed: formatUint64(c.failedConnections.Load()),
	}
}
