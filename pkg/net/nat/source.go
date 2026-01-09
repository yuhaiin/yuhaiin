package nat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/ringbuffer"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type sentPacket struct {
	src net.Addr
	buf []byte
}

type ContextCache struct {
	resolver  *netapi.ResolverOptions
	migrateID uint64
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
	close context.CancelFunc

	// notifySentPacket signals that there are packets ready to be processed and sent from sentPackets.
	notifySentPacket chan struct{}

	// notifyReceivedPacket signals that there are packets received from the remote ready to be written back.
	notifyReceivedPacket chan struct{}

	// loopStopTime stores the timestamp when the primary I/O loop stopped, used for idle timeout checks.
	loopStopTime atomic.Pointer[time.Time]

	// conn is the wrapped PacketConn to the remote destination.
	conn *wrapConn
	// wirteBack is a function to write received packets back to the original client.
	wirteBack *atomicx.Value[netapi.WriteBackFunc]

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
	// dispatchCache caches the dispatch decision for a destination, indicating how to route it.
	dispatchCache syncmap.SyncMap[uint64, netapi.Address]

	// loopStopped indicates atomically if the primary I/O loop (loopWriteBack) for this control is stopped.
	loopStopped atomic.Bool
}

func NewSourceChan(sniffer netapi.PacketSniffer, dialer netapi.Proxy) *SourceControl {
	ctx, cancel := context.WithCancel(context.Background())
	s := &SourceControl{
		ctx:                  ctx,
		close:                cancel,
		notifySentPacket:     make(chan struct{}, 1),
		notifyReceivedPacket: make(chan struct{}, 1),
		dialer:               dialer,
		sniffer:              sniffer,
		wirteBack: atomicx.NewValue(netapi.WriteBackFunc(func(b []byte, addr net.Addr) (int, error) {
			return 0, errors.ErrUnsupported
		})),
		sentPackets:     ringbuffer.NewRingBuffer[*netapi.Packet](8, configuration.MaxUDPUnprocessedPackets.Load),
		receivedPackets: ringbuffer.NewRingBuffer[sentPacket](8, configuration.MaxUDPUnprocessedPackets.Load),
	}

	now := time.Now()
	s.loopStopTime.Store(&now)
	process := ""
	s.lastProcess.Store(&process)

	go s.run()
	return s
}

func (u *SourceControl) Close() error {
	u.close()

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

	return nil
}

func (u *SourceControl) IsIdle() (time.Time, bool) {
	if u.loopStopped.Load() {
		return *u.loopStopTime.Load(), true
	}
	return time.Time{}, false
}

func (u *SourceControl) run() {
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
			return fmt.Errorf("ringbuffer is full, drop packet")
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
		pkt, ok := u.sentPackets.Pop()
		if !ok {
			break
		}

		err := u.handleOne(pkt)
		pkt.DecRef()
		if err != nil {
			if netapi.IsBlockError(err) {
				_ = u.Close()
				return
			}

			log.Select(u.logLevel(err)).Print("handle packet failed", "err", err, "last_process", *u.lastProcess.Load())
		}
	}
}

func (u *SourceControl) logLevel(err error) slog.Level {
	if configuration.IgnoreTimeoutErrorLog.Load() {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
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

		u.wirteBack.Store(pkt.WriteBack)
		u.conn = conn
		process := store.GetProcessName()
		u.lastProcess.Store(&process)
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

	go u.loopWriteBack(conn, pkt.Dst())

	return conn, nil
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
		dstAddr, err = t.dialer.Dispatch(ctx, pkt.Dst())
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
	_ = conn.SetReadDeadline(time.Now().Add(IdleTimeout))
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
}

func (u *SourceControl) loopWriteBack(p *wrapConn, dst netapi.Address) {
	ctx, cancel := context.WithCancel(u.ctx)
	u.loopStopped.Store(false)

	defer func() {
		cancel()
		now := time.Now()
		u.loopStopped.Store(true)
		u.loopStopTime.Store(&now)
		_ = p.Close()
	}()

	go func() {
		errCount := 0
	_loop:
		for {
			select {
			case <-ctx.Done():
				return
			case <-u.ctx.Done():
				return
			case <-u.notifyReceivedPacket:

				writeBack := u.wirteBack.Load()

				for {
					pkt, ok := u.receivedPackets.Pop()
					if !ok {
						continue _loop
					}

					_, err := writeBack(pkt.buf, u.parseAddr(pkt.src))
					pool.PutBytes(pkt.buf)

					if err != nil {
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
		_ = p.SetReadDeadline(time.Now().Add(IdleTimeout))
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

		if !u.receivedPackets.Push(sentPacket{from, data[:n]}) {
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

func (s *SourceControl) parseAddr(from net.Addr) net.Addr {
	faddr, err := netapi.ParseSysAddr(from)
	if err != nil {
		log.Error("parse addr failed", "err", err)
		return from
	}

	if addr, ok := s.reverseNATMap.Load(faddr.Comparable()); ok {
		// TODO: maybe two dst(fake ip) have same uaddr, need help
		from = addr
	}

	return from
}

type wrapConn struct {
	net.PacketConn
	closed atomic.Bool
}

func (w *wrapConn) Close() error {
	w.closed.Store(true)
	return w.PacketConn.Close()
}
