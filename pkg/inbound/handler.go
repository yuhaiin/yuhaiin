package inbound

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/net/sniff"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

var ErrStreamAdmissionLimit = errors.New("inbound: stream session limit")

type handler struct {
	dialer       netapi.Proxy
	table        *nat.Table
	globalBudget *trafficcontrol.Governor
	qos          *trafficcontrol.Manager
	streamScopes sync.Map // inbound ID/name -> *inboundStreamScope

	sniffer     *controlSniffer
	interceptor interface {
		Intercept(*netapi.Context, *netapi.StreamMeta) bool
	}
}

type inboundStreamScope struct {
	mu       sync.Mutex
	governor *trafficcontrol.Governor
	retired  bool
}

func (s *handler) acquireStreamScope(id string) (*inboundStreamScope, *trafficcontrol.Session, bool) {
	for {
		value, ok := s.streamScopes.Load(id)
		if !ok {
			value, _ = s.streamScopes.LoadOrStore(id, &inboundStreamScope{governor: trafficcontrol.NewGovernor(trafficcontrol.Limits{
				MaxSessions: 8192, SessionsPerSec: 1000, SessionBurst: 2048,
			}, s.globalBudget)})
		}
		scope := value.(*inboundStreamScope)
		scope.mu.Lock()
		current, ok := s.streamScopes.Load(id)
		if !ok || current != scope {
			scope.mu.Unlock()
			continue
		}
		lease, admitted := scope.governor.AcquireSession()
		scope.mu.Unlock()
		return scope, lease, admitted
	}
}

func (s *handler) releaseStreamScope(id string, scope *inboundStreamScope, lease *trafficcontrol.Session) {
	lease.Release()
	scope.mu.Lock()
	if scope.retired && scope.governor.Snapshot().Sessions == 0 {
		s.streamScopes.CompareAndDelete(id, scope)
	}
	scope.mu.Unlock()
}

// ForgetInboundScope retires a configuration identity. Existing streams keep
// their governor until the final lease is released; a re-added identity then
// shares that same quota instead of creating a second active budget.
func (s *handler) ForgetInboundScope(id string) {
	value, ok := s.streamScopes.Load(id)
	if !ok {
		return
	}
	scope := value.(*inboundStreamScope)
	scope.mu.Lock()
	scope.retired = true
	if scope.governor.Snapshot().Sessions == 0 {
		s.streamScopes.CompareAndDelete(id, scope)
	}
	scope.mu.Unlock()
}

func NewHandler(dialer netapi.Proxy) *handler {
	sniffer := newControlSniffer()
	root := trafficcontrol.NewGovernor(trafficcontrol.Limits{MaxSessions: 65536, SessionsPerSec: 4000, SessionBurst: 8192}, nil)
	qos := trafficcontrol.NewManager()
	h := &handler{
		qos:          qos,
		dialer:       dialer,
		table:        nat.NewTableWithParent(sniffer, dialer, root),
		globalBudget: root,
		sniffer:      sniffer,
	}
	h.table.SetTrafficControl(qos)
	return h
}

func (s *handler) logLevel(err error) slog.Level {
	level := netapi.LogLevel(err)
	if level == slog.LevelDebug {
		return slog.LevelDebug
	}

	if configuration.IgnoreDnsErrorLog.Load() {
		if _, ok := errors.AsType[*net.DNSError](err); ok {
			return slog.LevelDebug
		}
	}

	if configuration.IgnoreTimeoutErrorLog.Load() {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return slog.LevelDebug
		}

		if netOpErr, ok := errors.AsType[*net.OpError](err); ok && netOpErr.Timeout() {
			return slog.LevelDebug
		}

		if syscallErr, ok := errors.AsType[syscall.Errno](err); ok {
			switch syscallErr {
			case syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH:
				return slog.LevelDebug
			}
		}
	}

	return slog.LevelError
}

func (s *handler) Stream(ctx *netapi.Context, meta *netapi.StreamMeta) {
	if err := s.stream(ctx, meta); err != nil {
		if errors.Is(err, ErrStreamAdmissionLimit) {
			return
		} // overload is counted; avoid log storms
		log.Select(s.logLevel(err)).Print("inbound handler stream", "msg", err)
	}
}

func (s *handler) stream(store *netapi.Context, meta *netapi.StreamMeta) error {
	if s.globalBudget != nil {
		id := meta.InboundID
		if id == "" {
			id = meta.InboundName
		}
		scope, lease, ok := s.acquireStreamScope(id)
		if !ok {
			_ = meta.Src.Close()
			return ErrStreamAdmissionLimit
		}
		defer s.releaseStreamScope(id, scope, lease)
	}
	dst := meta.Address

	startNanoSeconds := system.CheapNowNano()

	meta.Src = s.sniffer.Stream(store, meta.Src)
	defer meta.Src.Close()
	if s.interceptor != nil && s.interceptor.Intercept(store, meta) {
		return nil
	}

	ctx, cancel := context.WithTimeout(store, configuration.Timeout)
	defer cancel()
	remote, err := s.dialer.Conn(ctx, dst)
	if err != nil {
		ne := netapi.NewDialError("tcp", err, dst)
		sniff := store.SniffHost()
		if sniff != "" {
			ne.Sniff = sniff
		}
		return ne
	}
	defer remote.Close()

	endNanoSeconds := system.CheapNowNano()

	metrics.Counter.AddStreamConnectDuration(time.Duration(endNanoSeconds - startNanoSeconds))

	process, pid, uid := store.GetProcess()

	ruleID, _ := store.MatchedRule()
	inboundID := meta.InboundID
	if inboundID == "" {
		inboundID = meta.InboundName
	}
	policy := s.qos.Resolve(inboundID, ruleID)
	relay.RelayShaped(store, meta.Src, remote, policy, "dst", dst, "src", store.Source,
		"process", process, "pid", pid, "uid", uid)

	return nil
}

func (s *handler) Packet(ctx context.Context, pack *netapi.Packet) {
	if err := s.table.Write(ctx, pack); err != nil {
		if errors.Is(err, nat.ErrSendPacketQueueFull) || errors.Is(err, nat.ErrNATSessionLimit) {
			// The metric records queue drops; per-packet logging can amplify congestion.
			return
		}
		log.Error("packet", "error", err)
	}
}

func (s *handler) Ping(ctx context.Context, pack *netapi.PingMeta) {
	resp, err := s.dialer.Ping(ctx, pack.Destination)
	if err != nil {
		log.Error("ping", "error", err, "src", pack.Source, "dst", pack.Destination)
	}

	if err := pack.WriteBack(resp, err); err != nil {
		log.Error("write back", "error", err, "src", pack.Source, "dst", pack.Destination)
	}
}

// TrafficStatus is a bounded, low-cardinality snapshot, not a flow-level
// telemetry feed. An inbound scope is a trusted configuration identity.
func (s *handler) TrafficStatus() trafficcontrol.Status {
	st := trafficcontrol.Status{Global: s.globalBudget.Snapshot(), NAT: s.table.ResourceStats(), Shaping: s.qos.Usage()}
	s.streamScopes.Range(func(key, value any) bool {
		if len(st.InboundScopes) >= 64 {
			st.Truncated = true
			return false
		}
		id, ok := key.(string)
		if ok {
			st.InboundScopes = append(st.InboundScopes, trafficcontrol.ScopeStatus{
				ID: id, Counters: value.(*inboundStreamScope).governor.Snapshot(),
			})
		}
		return true
	})
	return st
}

func (s *handler) Close() error {
	s.streamScopes.Range(func(key, _ any) bool {
		if id, ok := key.(string); ok {
			s.ForgetInboundScope(id)
		}
		return true
	})
	return s.table.Close()
}

type controlSniffer struct {
	sniffer *sniff.Sniffier
	enabled atomic.Bool
}

func newControlSniffer() *controlSniffer {
	return &controlSniffer{
		sniffer: sniff.New(),
	}
}

func (u *controlSniffer) Packet(ctx *netapi.Context, b []byte) {
	if u.enabled.Load() {
		u.sniffer.Packet(ctx, b)
	}
}

func (u *controlSniffer) Stream(ctx *netapi.Context, cc net.Conn) net.Conn {
	if u.enabled.Load() {
		return u.sniffer.Stream(ctx, cc)
	}
	return cc
}

func (c *controlSniffer) SetEnabled(enabled bool) {
	c.enabled.Store(enabled)
}
