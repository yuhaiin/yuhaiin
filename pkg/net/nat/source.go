package nat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/ringbuffer"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

// ErrSendPacketQueueFull reports a UDP packet dropped because a flow's send queue is full.
var ErrSendPacketQueueFull = errors.New("ringbuffer is full, drop packet")

type sentPacket struct {
	src     net.Addr
	srcAddr netapi.Address
	srcKey  uint64
	buf     []byte
}

type ContextCache struct {
	resolver  *netapi.ResolverOptions
	migrateID uint64
}

type replyBinding struct {
	source net.Addr
	write  netapi.WriteBackFunc
}

func newContextCache(store *netapi.Context) ContextCache {
	return ContextCache{
		resolver:  store.ConnOptions().Resolver(),
		migrateID: store.GetUDPMigrateID(),
	}
}

type SourceControl struct {
	ctx    context.Context
	dialer netapi.Proxy

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

	// resolvedIPCache caches the resolved IP address for a destination hostname.
	resolvedIPCache syncmap.SyncMap[uint64, *net.UDPAddr]
	// reverseNATMap maps the proxy's reply-from address back to the original client-requested destination for reverse NAT.
	reverseNATMap syncmap.SyncMap[uint64, netapi.Address]
	// hasReverseNAT marks whether this flow has ever needed reverse NAT remapping.
	hasReverseNAT atomic.Bool
	// dispatchCache caches the dispatch decision for a destination, indicating how to route it.
	dispatchCache syncmap.SyncMap[uint64, netapi.Address]

	// A failed first dial is idle too. Counting readers also prevents an old
	// connection's exit from marking its replacement idle.
	readers atomic.Int64
}

func NewSourceChan(sniffer netapi.PacketSniffer, dialer netapi.Proxy) *SourceControl {
	ctx, cancel := context.WithCancel(context.Background())
	s := &SourceControl{
		ctx:                  ctx,
		close:                cancel,
		done:                 make(chan struct{}),
		notifySentPacket:     make(chan struct{}, 1),
		notifyReceivedPacket: make(chan struct{}, 1),
		dialer:               dialer,
		sniffer:              sniffer,
		sentPackets:          ringbuffer.NewRingBuffer[*netapi.Packet](8, configuration.MaxUDPUnprocessedPackets.Load),
		receivedPackets:      ringbuffer.NewRingBuffer[sentPacket](8, configuration.MaxUDPUnprocessedPackets.Load),
	}
	s.reply.Store(&replyBinding{write: func([]byte, net.Addr) (int, error) { return 0, errors.ErrUnsupported }})

	now := time.Now()
	s.loopStopTime.Store(&now)
	process := ""
	s.lastProcess.Store(&process)

	go s.run()
	return s
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

		pkt.DecRef()
	}

	for {
		pkt, ok := u.receivedPackets.Pop()
		if !ok {
			break
		}

		pool.PutBytes(pkt.buf)
	}

}

func (u *SourceControl) IsIdle() (time.Time, bool) {
	if u.readers.Load() == 0 {
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
		u.drain()
		close(u.done)
	}()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-u.notifySentPacket:
			u.handle()
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
		pkt.IncRef()
		if !u.sentPackets.Push(pkt) {
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
	for {
		if u.ctx.Err() != nil {
			return
		}
		pkt, ok := u.sentPackets.Pop()
		if !ok {
			break
		}

		err := u.handleOne(pkt)
		pkt.DecRef()
		if err != nil {
			if netapi.IsBlockError(err) {
				// Close waits for run itself; signal cancellation here instead.
				u.close()
				return
			}

			log.Select(u.logLevel(err)).Print("handle packet failed", "err", err, "last_process", *u.lastProcess.Load())
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

func (u *SourceControl) handleOne(pkt *netapi.Packet) error {
	ctx := u.ctx

	// here is only one thread, so we don't need lock
	conn := u.conn

	if conn == nil || conn.closed.Load() {
		var err error

		store := netapi.GetContext(ctx)
		store.Source = pkt.Src()
		store.Destination = pkt.Dst()
		store.SetInboundName(pkt.InboundName())
		store.ConnOptions().SetIsUdp(true)

		if u.sniffer != nil {
			u.sniffer.Packet(store, pkt.GetPayload())
		}

		_, ok := pkt.Src().(*quic.QuicAddr)
		if !ok {
			src, err := netapi.ParseSysAddr(pkt.Src())
			if err == nil && !src.IsFqdn() {
				// here is only check none fqdn, so we don't need timeout
				srcAddr := src.(netapi.IPAddress).AddrPort()
				if srcAddr.Addr().Unmap().Is4() {
					store.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv4)
				}
			}
		}

		ctx = store

		conn, err = u.newPacketConn(store, pkt)
		if err != nil {
			return err
		}

		u.conn = conn
		process := store.GetProcessName()
		u.lastProcess.Store(&process)
	}
	if pkt.MigrateID != 0 {
		binding := u.reply.Load()
		if !sameReplySource(binding.source, pkt.Src()) {
			// The same migrate ID can arrive over a different TCP/HTTP2 stream
			// while the outbound UDP session is healthy. Retarget replies without
			// reopening that session or allocating a callback on every packet.
			u.reply.Store(&replyBinding{source: pkt.Src(), write: pkt.WriteBack})
		}
	}

	if err := u.write(ctx, pkt, conn); err != nil {
		return err
	}

	return nil
}

func (u *SourceControl) newPacketConn(store *netapi.Context, pkt *netapi.Packet) (*wrapConn, error) {
	store.SetUDPMigrateID(u.contextCache.migrateID)
	if store.GetUDPMigrateID() != 0 {
		log.Info("set migrate id", "id", store.GetUDPMigrateID())
	}

	ctx, cancel := context.WithTimeout(store, configuration.Timeout)
	defer cancel()

	dstpconn, err := u.dialer.PacketConn(ctx, pkt.Dst())
	if err != nil {
		return nil, err
	}

	u.contextCache = newContextCache(store)

	conn := &wrapConn{PacketConn: dstpconn}
	u.reply.Store(&replyBinding{source: pkt.Src(), write: pkt.WriteBack})

	// The caller releases pkt after handleOne returns; capture the address
	// before starting a worker that can outlive that packet reference.
	dst := pkt.Dst()
	u.readers.Add(1)
	u.workers.Go(func() { u.loopWriteBack(conn, dst) })

	return conn, nil
}

func sameReplySource(a, b net.Addr) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	// TCP/HTTP2 remote addresses are normally stable, comparable values or
	// pointers. Avoid String/ParseSysAddr allocations on that packet path.
	if reflect.TypeOf(a) == reflect.TypeOf(b) && reflect.TypeOf(a).Comparable() {
		return a == b
	}
	return a.Network() == b.Network() && a.String() == b.String()
}

func (u *SourceControl) writeReply(ctx context.Context, data []byte, addr net.Addr) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		binding := u.reply.Load()
		_, err := binding.write(data, addr)
		if err == nil || binding == u.reply.Load() {
			return err
		}
		// A reply to the old transport may fail after migration has installed
		// a new one. Retry its still-owned data there instead of closing the
		// healthy UDP session because of an obsolete callback's error.
	}
}

func (t *SourceControl) write(ctx context.Context, pkt *netapi.Packet, conn net.PacketConn) error {
	key := pkt.Dst().Comparable()

	// ! we need write to same ip when use fakeip/domain, eg: quic will need it to create stream
	udpAddr, ok := t.resolvedIPCache.Load(key)
	if ok {
		// load from cache, so we don't need to map addr, pkt is nil
		return t.WriteTo(pkt.GetPayload(), udpAddr, nil, conn)
	}

	store := netapi.GetContext(ctx)

	// cache fakeip/hosts/bypass address
	// for fullcone nat, we as much as possible write to same address
	dstAddr, ok := t.dispatchCache.Load(key)
	if !ok {
		// we route at [SourceControl.newPacketConn], here is skip
		store.ConnOptions().SetSkipRoute(true)

		var err error
		dstAddr, err = t.dialer.Dispatch(store, pkt.Dst())
		if err != nil {
			return fmt.Errorf("dispatch addr failed: %w", err)
		}

		if key != dstAddr.Comparable() {
			t.dispatchCache.Store(key, dstAddr)
		}
	}

	// check is need resolve
	if !dstAddr.IsFqdn() || t.contextCache.resolver.UdpSkipResolveTarget() {
		return t.WriteTo(pkt.GetPayload(), dstAddr, pkt.Dst(), conn)
	}

	store.ConnOptions().SetResolver(*t.contextCache.resolver)

	ctx, cancel := context.WithTimeout(store, time.Second*5)
	defer cancel()

	ips, err := netapi.ResolverIP(ctx, dstAddr.Hostname())
	if err != nil {
		return fmt.Errorf("resolve addr failed: %w", err)
	}
	udpAddr = ips.RandUDPAddr(dstAddr.Port())

	t.resolvedIPCache.Store(key, udpAddr)

	err = t.WriteTo(pkt.GetPayload(), udpAddr, pkt.Dst(), conn)
	if err != nil {
		return fmt.Errorf("write to addr failed: %w", err)
	}

	return nil
}

func (t *SourceControl) WriteTo(b []byte, realDst net.Addr, originDst netapi.Address, conn net.PacketConn) error {
	_, err := conn.WriteTo(b, realDst)
	refreshPacketReadDeadline(conn, udpIdleTimeout())
	if err == nil && originDst != nil {
		t.mapAddr(realDst, originDst)
	}
	if err != nil && errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (t *SourceControl) mapAddr(src net.Addr, dst netapi.Address) {
	srcAddr, err := netapi.ParseSysAddr(src)
	if err != nil {
		log.Error("parse addr failed", "err", err)
		return
	}

	srcKey := srcAddr.Comparable()
	dstKey := dst.Comparable()

	if srcKey == dstKey {
		return
	}

	t.reverseNATMap.Store(srcKey, dst)
	t.hasReverseNAT.Store(true)
}

func (u *SourceControl) loopWriteBack(p *wrapConn, dst netapi.Address) {
	ctx, cancel := context.WithCancel(u.ctx)
	closed := make(chan struct{})
	// Capture this connection, rather than u.conn: an older reader may exit
	// after a replacement has been installed and must never close that replacement.
	stopClose := context.AfterFunc(ctx, func() {
		_ = p.Close()
		close(closed)
	})
	writeDone := make(chan struct{})

	defer func() {
		cancel()
		// Cancellation must interrupt ReadFrom/WriteTo, not just wake the
		// queue worker. Wait for any close callback before releasing buffers.
		if !stopClose() {
			<-closed
		}
		_ = p.Close()
		<-writeDone
		now := time.Now()
		u.loopStopTime.Store(&now)
		u.readers.Add(-1)
	}()

	go func() {
		defer close(writeDone)
		errCount := 0
	_loop:
		for {
			select {
			case <-ctx.Done():
				return
			case <-u.ctx.Done():
				return
			case <-u.notifyReceivedPacket:

				for {
					pkt, ok := u.receivedPackets.Pop()
					if !ok {
						continue _loop
					}

					err := u.writeReply(ctx, pkt.buf, u.parseAddr(pkt.src, pkt.srcAddr, pkt.srcKey))
					pool.PutBytes(pkt.buf)

					if err != nil {
						if ctx.Err() != nil {
							return
						}
						if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
							_ = p.Close()
							return
						}

						errCount++

						if errCount > 13 {
							log.Warn("write back failed too many times(over 13 times)", "err", err, "dst", dst)
							_ = p.Close()
							return
						}

						log.Error("write back failed", "err", err)
					} else if errCount != 0 {
						errCount = 0
					}
				}
			}
		}
	}()

	for {
		data := pool.GetBytes(configuration.UDPBufferSize.Load())
		p.refreshReadDeadline(udpIdleTimeout())
		n, from, err := p.ReadFrom(data)
		if err != nil {
			if ignoreError(err) {
				log.Debug("read from proxy break", "err", err, "dst", dst)
			} else {
				log.Error("read from proxy failed", "err", err, "dst", dst)
			}
			pool.PutBytes(data)
			return
		}

		metrics.Counter.AddReceiveUDPPacket()
		metrics.Counter.AddReceiveUDPPacketSize(n)

		srcAddr, srcKey := parseComparableAddr(from, u.hasReverseNAT.Load())
		if !u.receivedPackets.Push(sentPacket{
			src:     from,
			srcAddr: srcAddr,
			srcKey:  srcKey,
			buf:     data[:n],
		}) {
			pool.PutBytes(data)
			metrics.Counter.AddReceiveUDPDroppedPacket()
			continue
		}

		select {
		case u.notifyReceivedPacket <- struct{}{}:
		default:
		}
	}
}

func ignoreError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed)
}

func parseComparableAddr(from net.Addr, needComparable bool) (netapi.Address, uint64) {
	if !needComparable {
		return nil, 0
	}

	faddr, err := netapi.ParseSysAddr(from)
	if err != nil {
		log.Error("parse addr failed", "err", err)
		return nil, 0
	}

	return faddr, faddr.Comparable()
}

func (s *SourceControl) parseAddr(from net.Addr, srcAddr netapi.Address, srcKey uint64) net.Addr {
	if srcKey != 0 {
		if addr, ok := s.reverseNATMap.Load(srcKey); ok {
			// TODO: maybe two dst(fake ip) have same uaddr, need help
			return addr
		}
	}

	if srcAddr != nil {
		return srcAddr
	}

	return from
}

type wrapConn struct {
	net.PacketConn
	closed                  atomic.Bool
	nextReadDeadlineRefresh atomic.Int64
	closeOnce               sync.Once
	closeErr                error
}

func refreshPacketReadDeadline(conn net.PacketConn, timeout time.Duration) {
	if wrapped, ok := conn.(*wrapConn); ok {
		wrapped.refreshReadDeadline(timeout)
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
}

func (w *wrapConn) refreshReadDeadline(timeout time.Duration) {
	if timeout <= 0 {
		return
	}

	now := time.Now()
	nowNano := now.UnixNano()
	next := w.nextReadDeadlineRefresh.Load()
	if next > nowNano {
		return
	}

	refreshInterval := timeout / 4
	if refreshInterval > 30*time.Second {
		refreshInterval = 30 * time.Second
	}
	if refreshInterval < time.Second {
		refreshInterval = time.Second
	}
	if !w.nextReadDeadlineRefresh.CompareAndSwap(next, now.Add(refreshInterval).UnixNano()) {
		return
	}

	deadline := now.Add(timeout + refreshInterval)
	if err := w.PacketConn.SetReadDeadline(deadline); err != nil {
		w.nextReadDeadlineRefresh.Store(0)
	}
}

func (w *wrapConn) Close() error {
	w.closed.Store(true)
	w.closeOnce.Do(func() { w.closeErr = w.PacketConn.Close() })
	return w.closeErr
}
