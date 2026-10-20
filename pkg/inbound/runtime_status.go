package inbound

import (
	"cmp"
	"context"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"slices"
	"strconv"
	"time"
)

type runtimeState struct {
	status, error string
	changedAt     int64
	events        []contract.RuntimeEvent
}

// recordState is called while mu is held. History is bounded and runtime-only.
func (l *Inbound) recordState(id, state, errorText string) {
	if l.states == nil {
		l.states = make(map[string]runtimeState)
	}
	previous := l.states[id]
	if previous.status == state && previous.error == errorText {
		return
	}
	previous.status, previous.error, previous.changedAt = state, errorText, time.Now().Unix()
	kind := "start"
	switch state {
	case "running":
		kind = "ready"
	case "failed", "degraded":
		kind = "fail"
	case "disabled", "stopping":
		kind = "stop"
	}
	l.eventID++
	previous.events = append(previous.events, contract.RuntimeEvent{ID: l.eventID, InboundID: id, Type: kind, State: state, Error: errorText, CreatedAt: previous.changedAt})
	if len(previous.events) > 100 {
		previous.events = slices.Clone(previous.events[len(previous.events)-100:])
	}
	l.states[id] = previous
}

func (l *Inbound) runtimeStatus(config contract.Inbound) contract.RuntimeStatus {
	l.mu.RLock()
	defer l.mu.RUnlock()
	id := cmp.Or(config.ID, config.Name)
	state := l.states[id]
	if state.status == "" {
		state.status = "disabled"
		if config.Enabled && !l.closed {
			state.status = "starting"
		}
	}
	listeners := []contract.RuntimeListener{{Kind: config.Protocol.Type, State: state.status, Listen: configuredListen(config)}}
	stats := contract.IngressStatistics{AcceptedStreams: "0", ReceivedPackets: "0", ReceivedPings: "0"}
	if entry, ok := l.store.Load(id); ok {
		if bound, ok := entry.server.(interface {
			listenerBindings() []contract.RuntimeListener
		}); ok {
			listeners = bound.listenerBindings()
			for i := range listeners {
				listeners[i].State = state.status
			}
		}
	}
	counters := l.countersByID[id]
	if counters == nil {
		if entry, ok := l.store.Load(id); ok {
			counters = entry.counters
		}
	}
	if counters != nil {
		stats.AcceptedStreams = strconv.FormatUint(counters.streams.Load(), 10)
		stats.ReceivedPackets = strconv.FormatUint(counters.packets.Load(), 10)
		stats.ReceivedPings = strconv.FormatUint(counters.pings.Load(), 10)
	}
	return contract.RuntimeStatus{ID: id, Name: config.Name, Enabled: config.Enabled, Status: state.status, LastError: state.error, ChangedAt: state.changedAt,
		Statistics: stats, Listeners: listeners}
}

func configuredListen(config contract.Inbound) string {
	if config.Network.TCPUDP != nil {
		return config.Network.TCPUDP.Host
	}
	if config.Network.QUIC != nil {
		return config.Network.QUIC.Host
	}
	if config.Protocol.Tun != nil {
		return config.Protocol.Tun.Name
	}
	if config.Protocol.Redir != nil {
		return config.Protocol.Redir.Host
	}
	if config.Protocol.TProxy != nil {
		return config.Protocol.TProxy.Host
	}
	if config.Protocol.Krunlet != nil {
		return config.Protocol.Krunlet.Socket
	}
	return ""
}

func (s *ContractStore) Statuses(ctx context.Context) ([]contract.RuntimeStatus, error) {
	configs, err := s.store.List(ctx)
	if err != nil {
		return nil, err
	}
	statuses := make([]contract.RuntimeStatus, 0, len(configs))
	for _, config := range configs {
		statuses = append(statuses, s.runtime.runtimeStatus(config))
	}
	return statuses, nil
}

func (s *ContractStore) Events(ctx context.Context, id string) ([]contract.RuntimeEvent, error) {
	if _, err := s.store.Get(ctx, id); err != nil {
		return nil, err
	}
	s.runtime.mu.RLock()
	defer s.runtime.mu.RUnlock()
	events := slices.Clone(s.runtime.states[id].events)
	slices.Reverse(events)
	return events, nil
}

func (s *ContractStore) Retry(ctx context.Context, id string) error {
	config, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	return s.runtime.SaveContract(config)
}
