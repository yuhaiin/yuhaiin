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

func (m ConnectionMonitor) Traffic(ctx context.Context, interval string, from, to time.Time) (contractconnection.TrafficSeries, error) {
	if m.connections == nil {
		return contractconnection.TrafficSeries{}, errors.New("connections controller is unavailable")
	}
	return m.connections.Traffic(ctx, interval, from, to)
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
