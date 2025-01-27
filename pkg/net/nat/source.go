package nat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/ringbuffer"
)

type sentPacket struct {
	buf []byte
	src net.Addr
}

type Context struct {
	resolver    netapi.ContextResolver
	migrateID   uint64
	skipResolve bool
}

func newContext(store *netapi.Context) Context {
	return Context{
		resolver:    store.Resolver,
		migrateID:   store.UDPMigrateID,
		skipResolve: store.Resolver.SkipResolve,
	}
}

type SourceControl struct {
	ctx   context.Context
	close context.CancelFunc

	sentPacketMx     sync.Mutex
	sentPackets      ringbuffer.RingBuffer[*netapi.Packet]
	notifySentPacket chan struct{}

	receivedPacketMx     sync.Mutex
	receivedPackets      ringbuffer.RingBuffer[sentPacket]
	notifyReceivedPacket chan struct{}

	onRemove func(*SourceControl)

	addrStore addrStore
	dialer    netapi.Proxy
	stopTimer *stopTimer
	context   Context
	conn      *wrapConn
	wirteBack *atomicx.Value[netapi.WriteBack]

	sniffer netapi.PacketSniffer
}

func NewSourceChan(sniffer netapi.PacketSniffer, dialer netapi.Proxy, onRemove func(*SourceControl)) *SourceControl {
	ctx, cancel := context.WithCancel(context.Background())
	s := &SourceControl{
		ctx:                  ctx,
		close:                cancel,
		notifySentPacket:     make(chan struct{}, 1),
		notifyReceivedPacket: make(chan struct{}, 1),
		onRemove:             onRemove,
		dialer:               dialer,
		sniffer:              sniffer,
		wirteBack: atomicx.NewValue[netapi.WriteBack](netapi.WriteBackFunc(func(b []byte, addr net.Addr) (int, error) {
			return 0, errors.ErrUnsupported
		})),
	}

	s.sentPackets.Init(8)
	s.receivedPackets.Init(8)

	s.stopTimer = NewStopTimer(IdleTimeout, func() { _ = s.Close() })
	s.stopTimer.Start()
	go s.run()

	return s
}

func (u *SourceControl) Close() error {
	u.stopTimer.Stop()
	u.close()
	u.onRemove(u)

	u.sentPacketMx.Lock()
	defer u.sentPacketMx.Unlock()

	for !u.sentPackets.Empty() {
		pkt := u.sentPackets.PopFront()
		pkt.DecRef()
	}

	u.receivedPacketMx.Lock()
	defer u.receivedPacketMx.Unlock()

	for !u.receivedPackets.Empty() {
		pkt := u.receivedPackets.PopFront()
		pool.PutBytes(pkt.buf)
	}

	return nil
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
	pkt.IncRef()
	select {
	case <-u.ctx.Done():
		pkt.DecRef()
		return u.ctx.Err()
	case <-ctx.Done():
		pkt.DecRef()
		return ctx.Err()

	default:
		u.sentPacketMx.Lock()
		if u.sentPackets.Len() >= configuration.MaxUDPUnprocessedPackets {
			u.sentPacketMx.Unlock()
			metrics.Counter.AddSendUDPDroppedPacket()
			return fmt.Errorf("ringbuffer is full, drop packet")
		}

		u.sentPackets.PushBack(pkt)
		u.sentPacketMx.Unlock()

		select {
		case u.notifySentPacket <- struct{}{}:
		default:
		}
		return nil
	}
}

func (u *SourceControl) handle() {
	u.sentPacketMx.Lock()
	numPackets := u.sentPackets.Len()
	if numPackets == 0 {
		u.sentPacketMx.Unlock()
		return
	}

	var hasMorePackets bool

	for i := 0; i < numPackets; i++ {
		if i > 0 {
			u.sentPacketMx.Lock()
		}

		hasMorePackets = !u.sentPackets.Empty()
		if !hasMorePackets {
			u.sentPacketMx.Unlock()
			return
		}

		pkt := u.sentPackets.PopFront()
		u.sentPacketMx.Unlock()

		if err := u.handleOne(pkt); err != nil {
			if netapi.IsBlockError(err) {
				u.Close()
				pkt.DecRef()
				return
			}
			log.Error("handle packet failed", "err", err)
		}

		pkt.DecRef()
	}
}

func (u *SourceControl) handleOne(pkt *netapi.Packet) error {
	ctx := u.ctx

	// here is only one thread, so we don't need lock
	conn := u.conn

	if conn == nil || conn.closed.Load() {
		var err error

		store := netapi.GetContext(ctx)
		store.Source = pkt.Src
		store.Destination = pkt.Dst

		u.sniffer.Packet(store, pkt.Payload)

		_, ok := pkt.Src.(*quic.QuicAddr)
		if !ok {
			src, err := netapi.ParseSysAddr(pkt.Src)
			if err == nil && !src.IsFqdn() {
				// here is only check none fqdn, so we don't need timeout
				srcAddr, _ := dialer.ResolverAddrPort(store, src)
				if srcAddr.Addr().Unmap().Is4() {
					store.Resolver.Mode = netapi.ResolverModePreferIPv4
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
	}

	return u.write(ctx, pkt, conn)
}

func (u *SourceControl) newPacketConn(store *netapi.Context, pkt *netapi.Packet) (*wrapConn, error) {
	store.UDPMigrateID = u.context.migrateID
	if store.UDPMigrateID != 0 {
		log.Info("set migrate id", "id", store.UDPMigrateID)
	}

	ctx, cancel := context.WithTimeout(store, configuration.Timeout)
	defer cancel()

	dstpconn, err := u.dialer.PacketConn(ctx, pkt.Dst)
	if err != nil {
		return nil, err
	}

	u.stopTimer.Stop()
	u.context = newContext(store)

	conn := &wrapConn{PacketConn: dstpconn}

	go u.loopWriteBack(conn, pkt.Dst)

	return conn, nil
}

func (t *SourceControl) write(ctx context.Context, pkt *netapi.Packet, conn net.PacketConn) error {
	key := pkt.Dst.String()

	// ! we need write to same ip when use fakeip/domain, eg: quic will need it to create stream
	udpAddr, ok := t.addrStore.LoadUdp(key)
	if ok {
		// load from cache, so we don't need to map addr, pkt is nil
		return t.WriteTo(pkt.Payload, udpAddr, nil, conn)
	}

	// cache fakeip/hosts/bypass address
	// for fullcone nat, we as much as possible write to same address
	dstAddr, ok := t.addrStore.LoadDispatch(key)
	if !ok {
		// we route at [SourceControl.newPacketConn], here is skip
		ctx = context.WithValue(ctx, netapi.SkipRouteKey{}, true)

		var err error
		dstAddr, err = t.dialer.Dispatch(ctx, pkt.Dst)
		if err != nil {
			return fmt.Errorf("dispatch addr failed: %w", err)
		}

		if !pkt.Dst.Equal(dstAddr) {
			t.addrStore.StoreDispatch(key, dstAddr)
		}
	}

	// check is need resolve
	if !dstAddr.IsFqdn() || t.context.skipResolve {
		return t.WriteTo(pkt.Payload, dstAddr, pkt.Dst, conn)
	}

	store := netapi.GetContext(ctx)
	store.Resolver = t.context.resolver

	ctx, cancel := context.WithTimeout(store, time.Second*5)
	defer cancel()

	udpAddr, err := dialer.ResolveUDPAddr(ctx, dstAddr)
	if err != nil {
		return fmt.Errorf("resolve addr failed: %w", err)
	}
	t.addrStore.StoreUdp(key, udpAddr)

	err = t.WriteTo(pkt.Payload, udpAddr, pkt.Dst, conn)
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
	srcStr := src.String()
	dstStr := dst.String()

	if srcStr == dstStr {
		return
	}

	t.addrStore.StoreOrigin(srcStr, dst)
}

func (u *SourceControl) loopWriteBack(p *wrapConn, dst netapi.Address) {
	ctx, cancel := context.WithCancel(u.ctx)

	defer func() {
		cancel()
		u.stopTimer.Start()
		p.Close()
	}()

	go func() {
	_loop:
		for {
			select {
			case <-ctx.Done():
				return
			case <-u.ctx.Done():
				p.Close()
				return
			case <-u.notifyReceivedPacket:
				u.receivedPacketMx.Lock()
				numPackets := u.receivedPackets.Len()

				if numPackets == 0 {
					u.receivedPacketMx.Unlock()
					continue
				}

				writeBack := u.wirteBack.Load()

				var hasMorePackets bool
				for i := 0; i < numPackets; i++ {
					if i > 0 {
						u.receivedPacketMx.Lock()
					}

					hasMorePackets = !u.receivedPackets.Empty()
					if !hasMorePackets {
						u.receivedPacketMx.Unlock()
						continue _loop
					}

					pkt := u.receivedPackets.PopFront()
					u.receivedPacketMx.Unlock()

					_, err := writeBack.WriteBack(pkt.buf, u.parseAddr(pkt.src))
					pool.PutBytes(pkt.buf)

					if err != nil {
						if errors.Is(err, net.ErrClosed) {
							p.Close()
							return
						}

						log.Error("write back failed", "err", err)
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

		u.receivedPacketMx.Lock()
		if u.receivedPackets.Len() >= configuration.MaxUDPUnprocessedPackets {
			u.receivedPacketMx.Unlock()
			pool.PutBytes(data)
			metrics.Counter.AddReceiveUDPDroppedPacket()
			continue
		}

		u.receivedPackets.PushBack(sentPacket{data[:n], from})
		u.receivedPacketMx.Unlock()

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
		errors.Is(err, io.EOF)
}

func (s *SourceControl) parseAddr(from net.Addr) net.Addr {
	faddr, err := netapi.ParseSysAddr(from)
	if err != nil {
		log.Error("parse addr failed", "err", err)
		return from
	}

	if addr, ok := s.addrStore.LoadOrigin(faddr.String()); ok {
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

type stopTimer struct {
	timer *time.Timer
	mu    sync.Mutex
	do    func()
	d     time.Duration
}

func NewStopTimer(duration time.Duration, do func()) *stopTimer {
	return &stopTimer{do: do, d: duration}
}

func (s *stopTimer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
}

func (s *stopTimer) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.timer == nil {
		s.timer = time.AfterFunc(s.d, s.do)
	} else {
		s.timer.Reset(s.d)
	}
}
