package nat

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/ringbuffer"
)

// ErrSendPacketQueueFull reports a UDP packet dropped because a flow's send queue is full.
var ErrSendPacketQueueFull = errors.New("ringbuffer is full, drop packet")

type sentPacket struct {
	from net.Addr
	real net.Addr
	buf  []byte
	conn *wrapConn
}

type ContextCache struct {
	resolver  *netapi.ResolverOptions
	migrateID uint64
}

type replyBinding struct {
	inboundID string
	writer    netapi.WriteBack
	source    net.Addr
	write     func(context.Context, []byte, net.Addr) (int, error)
	ctx       context.Context
	cancel    context.CancelFunc
}

func newContextCache(store *netapi.Context) ContextCache {
	return ContextCache{
		resolver:  store.ConnOptions().Resolver(),
		migrateID: store.GetUDPMigrateID(),
	}
}

type SourceControl struct {
	access            netapi.TrafficAccessSession
	accessCancel      context.CancelCauseFunc
	identity          atomic.Pointer[proxyauth.Identity]
	ctx               context.Context
	dialer            netapi.Proxy
	destinationLeaser destinationLeaser
	// Only the sender owns leases; mapped destinations remain pinned until all
	// readers and replies stop, including across outbound socket migration.
	destinationLeases map[uint64]*destinationLease
	sessionLease      *trafficcontrol.Session
	queueBudget       trafficcontrol.BufferedResources
	trafficControl    trafficcontrol.PolicyResolver

	// sniffer is an optional packet sniffer for observability or traffic analysis.
	sniffer netapi.PacketSniffer
	// close is the cancel function associated with ctx, used to terminate the SourceControl.
	close   context.CancelFunc
	done    chan struct{}
	workers sync.WaitGroup
	queueMu sync.Mutex // Prevents enqueue after the shutdown drain.

	// notifySentPacket signals that there are packets ready to be processed and sent from sentPackets.
	notifySentPacket chan struct{}

	// notifyReceivedPacket signals that there are packets received from the remote ready to be written back.
	notifyReceivedPacket chan struct{}

	// loopStopTime stores the timestamp when the primary I/O loop stopped, used for idle timeout checks.
	loopStopTime atomic.Pointer[time.Time]

	// conn is the wrapped PacketConn to the remote destination.
	conn *wrapConn
	// reply follows the current inbound transport independently of the reused
	// outbound PacketConn. Its identity also detects migration during a write.
	reply atomic.Pointer[replyBinding]

	// sentPackets is a ring buffer holding packets waiting to be sent to the remote destination.
	sentPackets *ringbuffer.RingBuffer[*netapi.Packet]
	// receivedPackets is a ring buffer holding packets received from the remote, waiting to be sent back to the client.
	receivedPackets *ringbuffer.RingBuffer[sentPacket]

	// lastProcess stores the name of the last process associated with this flow, primarily for logging.
	lastProcess atomic.Pointer[string]

	// contextCache holds flow-specific options such as resolver and UDP migration ID.
	contextCache ContextCache

	// mapper belongs to the logical outbound session. Old readers retain their
	// own mapper when a non-migrating connection is replaced.
	mapper *addressMapper

	// Only run owns pending resolutions and their retained packet references.
	resolutions    map[uint64]*pendingResolution
	resolveQueue   []*pendingResolution
	resolved       chan resolutionResult
	resolving      int
	pendingPackets int
	replyDone      chan struct{}
	pending        atomic.Int64

	// A failed first dial is idle too. Counting readers also prevents an old
	// connection's exit from marking its replacement idle.
	readers atomic.Int64
}

func NewSourceChan(sniffer netapi.PacketSniffer, dialer netapi.Proxy) *SourceControl {
	return newSourceChan(sniffer, dialer, nil, nil, nil)
}

// Construct the ownership boundary before starting workers: a source may
// retire without an external caller retaining it long enough to call Close.
func newSourceChan(sniffer netapi.PacketSniffer, dialer netapi.Proxy, lease *trafficcontrol.Session, budget trafficcontrol.BufferedResources, qos trafficcontrol.PolicyResolver) *SourceControl {
	s, _ := newSourceChanWithAccess(sniffer, dialer, lease, budget, qos, nil, netapi.TrafficSubject{})
	return s
}

func newSourceChanWithAccess(sniffer netapi.PacketSniffer, dialer netapi.Proxy, lease *trafficcontrol.Session, budget trafficcontrol.BufferedResources, qos trafficcontrol.PolicyResolver, access netapi.TrafficAccess, subject netapi.TrafficSubject) (*SourceControl, error) {
	if budget == nil {
		budget = trafficcontrol.UnlimitedBudget()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &SourceControl{
		sessionLease:         lease,
		queueBudget:          budget,
		trafficControl:       qos,
		ctx:                  ctx,
		mapper:               newAddressMapper(),
		resolutions:          make(map[uint64]*pendingResolution),
		resolved:             make(chan resolutionResult, maxConcurrentResolutions),
		replyDone:            make(chan struct{}),
		close:                cancel,
		done:                 make(chan struct{}),
		notifySentPacket:     make(chan struct{}, 1),
		notifyReceivedPacket: make(chan struct{}, 1),
		dialer:               dialer,
		sniffer:              sniffer,
		sentPackets:          ringbuffer.NewRingBuffer[*netapi.Packet](8, configuration.MaxUDPUnprocessedPackets.Load),
		receivedPackets:      ringbuffer.NewRingBuffer[sentPacket](8, configuration.MaxUDPUnprocessedPackets.Load),
	}
	if access != nil {
		parent := context.Background()
		if subject.Identity != nil && subject.Identity.Context != nil {
			parent = subject.Identity.Context
		}
		lifetime, revoke := context.WithCancelCause(parent)
		session, err := access.NewSession(subject, func(cause error) { revoke(cause); cancel() })
		if err != nil || session == nil {
			cancel()
			revoke(netapi.ErrTrafficAccessDenied)
			lease.Release()
			if err == nil {
				err = netapi.ErrTrafficAccessDenied
			}
			return nil, err
		}
		s.access, s.accessCancel = session, revoke
		s.ctx = netapi.WithTrafficAuthorization(ctx, session, lifetime)
	}
	s.reply.Store(&replyBinding{ctx: s.ctx, cancel: func() {}, write: func(context.Context, []byte, net.Addr) (int, error) { return 0, errors.ErrUnsupported }})
	s.destinationLeaser, _ = dialer.(destinationLeaser)

	now := time.Now()
	s.loopStopTime.Store(&now)
	process := ""
	s.lastProcess.Store(&process)

	go s.runReply()
	go s.run()
	return s, nil
}

func (u *SourceControl) Close() error {
	// This destroys the control itself. Closing one outbound connection only
	// ends its reader; run and contextCache survive for UOT reconnection.
	u.close()
	<-u.done
	return nil
}

func (u *SourceControl) drain() {
	u.queueMu.Lock()
	defer u.queueMu.Unlock()
	for {
		pkt, ok := u.sentPackets.Pop()
		if !ok {
			break
		}

		u.queueBudget.ReleaseQueueBytes(int64(len(pkt.GetPayload())))
		pkt.DecRef()
		u.pending.Add(-1)
	}

	for {
		pkt, ok := u.receivedPackets.Pop()
		if !ok {
			break
		}

		u.queueBudget.ReleaseQueueBytes(int64(len(pkt.buf)))
		pool.PutBytes(pkt.buf)
	}

}

func (u *SourceControl) IsIdle() (time.Time, bool) {
	if u.pending.Load() == 0 && u.readers.Load() == 0 {
		return *u.loopStopTime.Load(), true
	}
	return time.Time{}, false
}

func (u *SourceControl) run() {
	defer func() {
		u.close()
		// All reader workers are started by this goroutine, so Wait cannot
		// race with a future Add. Drain only after producers have exited.
		u.workers.Wait()
		<-u.replyDone
		u.drainResolutions()
		u.drain()
		u.releaseDestinationLeases()
		if u.access != nil {
			u.access.Close()
			u.accessCancel(netapi.ErrTrafficSessionClosed)
		}
		u.sessionLease.Release()
		close(u.done)
	}()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-u.notifySentPacket:
			u.handle()
		case result := <-u.resolved:
			u.finishResolution(result)
		}
	}
}

func (u *SourceControl) WritePacket(ctx context.Context, pkt *netapi.Packet) error {
	u.queueMu.Lock()
	defer u.queueMu.Unlock()
	if err := u.ctx.Err(); err != nil {
		return err
	}
	select {
	case <-u.ctx.Done():
		return u.ctx.Err()
	case <-ctx.Done():
		return ctx.Err()

	default:
		if !u.queueBudget.ReserveQueueBytes(int64(len(pkt.GetPayload()))) {
			metrics.Counter.AddSendUDPDroppedPacket()
			return ErrSendPacketQueueFull
		}
		pkt.IncRef()
		u.pending.Add(1)
		if !u.sentPackets.Push(pkt) {
			u.queueBudget.ReleaseQueueBytes(int64(len(pkt.GetPayload())))
			u.pending.Add(-1)
			pkt.DecRef()
			metrics.Counter.AddSendUDPDroppedPacket()
			return ErrSendPacketQueueFull
		}

		select {
		case u.notifySentPacket <- struct{}{}:
		default:
		}
		return nil
	}
}

func (u *SourceControl) handle() {
	for range 64 {
		if u.ctx.Err() != nil {
			return
		}
		pkt, ok := u.sentPackets.Pop()
		if !ok {
			break
		}

		transferred, err := u.handleOneOwned(pkt, true)
		if !transferred {
			u.queueBudget.ReleaseQueueBytes(int64(len(pkt.GetPayload())))
		}
		pkt.DecRef()
		u.pending.Add(-1)
		if err != nil {
			if netapi.IsBlockError(err) {
				// A rejected target must not poison the full-cone source session.
				continue
			}

			u.logPacketError(err)
		}
	}
	if u.sentPackets.Len() != 0 {
		select {
		case u.notifySentPacket <- struct{}{}:
		default:
		}
	}
}

func (u *SourceControl) logLevel(err error) slog.Level {
	if configuration.IgnoreTimeoutErrorLog.Load() {
		if _, ok := errors.AsType[*net.DNSError](err); ok {
			return slog.LevelDebug
		}
	}

	if configuration.IgnoreTimeoutErrorLog.Load() && errors.Is(err, context.DeadlineExceeded) {
		return slog.LevelDebug
	}

	return slog.LevelError
}

func (u *SourceControl) logPacketError(err error) {
	if errors.Is(err, errReverseMappingFull) {
		metrics.Counter.AddSendUDPDroppedPacket()
		return
	}
	if netapi.IsBlockError(err) || errors.Is(err, context.Canceled) || errors.Is(err, ErrSendPacketQueueFull) {
		return
	}
	log.Select(u.logLevel(err)).Print("handle packet failed", "err", err, "last_process", *u.lastProcess.Load())
}
func maxPendingPackets() int { return max(1, configuration.MaxUDPUnprocessedPackets.Load()) }

// Retiring and queue admission share the same lock. Once retired, a writer
// retries through Table and cannot enqueue into a control removed by cleanup.
func (u *SourceControl) retireIdle(timeout time.Duration) bool {
	u.queueMu.Lock()
	defer u.queueMu.Unlock()
	stopped, idle := u.IsIdle()
	if !idle || time.Since(stopped) <= timeout {
		return false
	}
	u.close()
	return true
}

func (u *SourceControl) bindIdentity(identity *proxyauth.Identity) {
	u.identity.Store(identity)
	stop := context.AfterFunc(identity.Context, u.close)
	context.AfterFunc(u.ctx, func() { stop() })
}
func (u *SourceControl) identityValid() bool { return u.identity.Load().Valid() }

func (u *SourceControl) resolvePolicy(inboundID, routeID string) trafficcontrol.Policy {
	return trafficcontrol.ResolveAuthenticatedPolicy(u.trafficControl, inboundID, routeID, u.identity.Load())
}
