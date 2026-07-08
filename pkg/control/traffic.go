package control

import (
	"context"
	json "encoding/json/v2"
	"errors"

	schemaapi "github.com/Asutorufa/yuhaiin/pkg/schema/api"
)

type Traffic interface {
	Totals(ctx context.Context) (*schemaapi.TrafficTotals, error)
	Watch(ctx context.Context) (<-chan schemaapi.TrafficEvent, error)
}

type TrafficAdapter struct {
	Connections ConnectionsPort
}

func (p TrafficAdapter) Totals(ctx context.Context) (*schemaapi.TrafficTotals, error) {
	if p.Connections == nil {
		return nil, errors.New("connections service is nil")
	}

	total, err := p.Connections.Total(ctx, &schemaapi.Empty{})
	if err != nil {
		return nil, err
	}

	return &schemaapi.TrafficTotals{
		Download: total.GetDownload(),
		Upload:   total.GetUpload(),
		Counters: total.GetCounters(),
	}, nil
}

func (p TrafficAdapter) Watch(ctx context.Context) (<-chan schemaapi.TrafficEvent, error) {
	if p.Connections == nil {
		return nil, errors.New("connections service is nil")
	}

	events := make(chan schemaapi.TrafficEvent, 32)
	stream := &notifyStream{
		ctx:    ctx,
		events: events,
	}

	go func() {
		defer close(events)
		_ = p.Connections.Notify(&schemaapi.Empty{}, stream)
	}()

	return events, nil
}

type notifyStream struct {
	ctx    context.Context
	events chan<- schemaapi.TrafficEvent
}

func (s *notifyStream) Send(data *schemaapi.NotifyData) error {
	event, ok, err := toTrafficEvent(data)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case s.events <- event:
		return nil
	}
}

func (s *notifyStream) Context() context.Context { return s.ctx }

func toTrafficEvent(data *schemaapi.NotifyData) (schemaapi.TrafficEvent, bool, error) {
	switch {
	case data.GetTotalFlow() != nil:
		b, err := json.Marshal(data.GetTotalFlow())
		if err != nil {
			return schemaapi.TrafficEvent{}, false, err
		}
		return schemaapi.TrafficEvent{Type: "total_flow", Payload: b}, true, nil
	case data.GetNotifyNewConnections() != nil:
		b, err := json.Marshal(data.GetNotifyNewConnections())
		if err != nil {
			return schemaapi.TrafficEvent{}, false, err
		}
		return schemaapi.TrafficEvent{Type: "connections_added", Payload: b}, true, nil
	case data.GetNotifyRemoveConnections() != nil:
		b, err := json.Marshal(data.GetNotifyRemoveConnections())
		if err != nil {
			return schemaapi.TrafficEvent{}, false, err
		}
		return schemaapi.TrafficEvent{Type: "connections_removed", Payload: b}, true, nil
	default:
		return schemaapi.TrafficEvent{}, false, nil
	}
}
