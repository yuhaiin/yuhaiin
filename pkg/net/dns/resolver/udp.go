package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

func init() {
	Register("udp", NewDoU)
}

func udpCacheKey(id uint16, question netapi.DNSQuestion) string {
	var digits [10]byte
	identifier := strconv.AppendUint(digits[:0:5], uint64(id), 10)
	typ := strconv.AppendUint(digits[5:5], uint64(question.Qtype), 10)
	var key strings.Builder
	key.Grow(len(identifier) + len(question.Name) + len(typ) + 2)
	_, _ = key.Write(identifier)
	_ = key.WriteByte(':')
	_, _ = key.WriteString(question.Name)
	_ = key.WriteByte('|')
	_, _ = key.Write(typ)
	return key.String()
}

type udpresp struct {
	ctx     context.Context
	cancel  context.CancelFunc
	msg     atomic.Pointer[dns.Msg]
	session atomic.Pointer[udpSession]
	failure atomic.Pointer[error]
}

func (r *udpresp) fail(err error) {
	r.failure.CompareAndSwap(nil, new(err))
	r.cancel()
}

// udpSession owns only the queries sent on this exact socket. A reader from
// an obsolete socket cannot cancel requests or clear the replacement socket.
type udpSession struct {
	net.PacketConn
	mu      sync.Mutex
	pending map[*udpresp]struct{}
	closed  bool
}

func (s *udpSession) add(r *udpresp) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.pending[r] = struct{}{}
	r.session.Store(s)
	return nil
}

func (s *udpSession) remove(r *udpresp) {
	s.mu.Lock()
	delete(s.pending, r)
	s.mu.Unlock()
}

func (s *udpSession) closeWithError(err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	pending := s.pending
	s.pending = nil
	s.mu.Unlock()
	_ = s.Close()
	for r := range pending {
		r.fail(err)
	}
}

func (r *udpresp) setMsg(msg *dns.Msg) {
	// Publish the response before waking the waiting query.
	r.msg.Store(msg)
	r.cancel()
}

type udpPacket struct {
	ctx      context.Context
	question []byte
	response *udpresp
}

type udp struct {
	addr       netapi.Address
	staticAddr *net.UDPAddr

	ctx    context.Context
	cancel context.CancelFunc
	wchan  chan *udpPacket
	config Config

	sender  syncmap.SyncMap[string, *udpresp]
	done    chan struct{}
	readers sync.WaitGroup
}

func (u *udp) Close() error {
	u.cancel()
	if u.done != nil {
		<-u.done
		u.readers.Wait()
	}
	return nil
}

func (u *udp) handleResponse(packet *udpSession) error {
	buf := pool.GetBytes(nat.MaxSegmentSize)
	defer pool.PutBytes(buf)

	for {
		_ = packet.SetReadDeadline(time.Now().Add(time.Minute))
		n, _, err := packet.ReadFrom(buf)
		_ = packet.SetReadDeadline(time.Time{})
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Warn("dns udp read failed, try to re-dial", "err", err)
			}
			return err
		}

		msg := &dns.Msg{}
		msg.Data = append(msg.Data, buf[:n]...)
		if err := msg.Unpack(); err != nil {
			log.Warn("parse dns message failed", "err", err)
			continue
		}

		if len(msg.Question) == 0 {
			log.Warn("no question", "msg", msg)
			continue
		}

		send, ok := u.sender.Load(udpCacheKey(msg.ID, netapi.DNSQuestionFromRR(msg.Question[0])))
		if !ok || send == nil {
			continue
		}
		if send.session.Load() != packet {
			continue
		}

		send.setMsg(msg)
	}
}

func (u *udp) loopWrite() {
	defer close(u.done)
	var mu sync.RWMutex
	var packetConn *udpSession

	retire := func(old *udpSession, err error) {
		mu.Lock()
		if packetConn == old {
			packetConn = nil
		}
		mu.Unlock()
		if old != nil {
			old.closeWithError(err)
		}
	}

	dial := func() (*udpSession, error) {
		mu.RLock()
		pc := packetConn
		mu.RUnlock()

		if pc != nil {
			return pc, nil
		}

		mu.Lock()
		defer mu.Unlock()

		if packetConn != nil {
			return packetConn, nil
		}

		addr, err := ParseAddr("udp", u.config.Host, "53")
		if err != nil {
			return nil, fmt.Errorf("parse addr failed: %w", err)
		}

		ctx, cancel := context.WithTimeout(u.ctx, configuration.Timeout)
		defer cancel()

		raw, err := u.config.Dialer.PacketConn(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("get packetConn failed: %w", err)
		}

		packetConn = &udpSession{PacketConn: raw, pending: make(map[*udpresp]struct{})}
		session := packetConn
		u.readers.Go(func() {
			err := u.handleResponse(session)
			retire(session, err)
		})

		return packetConn, nil
	}

	write := func(p *udpPacket) error {
		pk, err := dial()
		if err != nil {
			return fmt.Errorf("init packetConn failed: %w", err)
		}

		uaddr, err := u.udpAddr()
		if err != nil {
			return fmt.Errorf("resolve udp addr failed: %w", err)
		}
		if err := pk.add(p.response); err != nil {
			retire(pk, err)
			return err
		}

		if err := pk.SetWriteDeadline(time.Now().Add(configuration.ResolverTimeout)); err != nil {
			return fmt.Errorf("set packetConn write deadline: %w", err)
		}
		_, err = pk.WriteTo(p.question, uaddr)
		if resetErr := pk.SetWriteDeadline(time.Time{}); resetErr != nil && err == nil {
			err = resetErr
		}
		if err != nil {
			retire(pk, err)
			return fmt.Errorf("write to packetConn failed: %w", err)
		}

		return nil
	}

	for {
		select {
		case p := <-u.wchan:
			select {
			case <-p.ctx.Done():
				continue
			default:
				if err := write(p); err != nil {
					p.response.fail(err)
					log.Warn("udp dns write failed", "err", err)
				}
			}

		case <-u.ctx.Done():
			mu.RLock()
			old := packetConn
			mu.RUnlock()
			retire(old, context.Canceled)
			return
		}
	}
}

func (u *udp) udpAddr() (*net.UDPAddr, error) {
	if !u.addr.IsFqdn() {
		if u.staticAddr != nil {
			return u.staticAddr, nil
		}
		return net.UDPAddrFromAddrPort(u.addr.(netapi.IPAddress).AddrPort()), nil
	}

	ctx, cancel := context.WithTimeout(u.ctx, configuration.ResolverTimeout)
	ips, err := netapi.ResolverIP(ctx, u.addr.Hostname())
	cancel()
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr failed: %w", err)
	}

	return ips.RandUDPAddr(u.addr.Port()), nil
}

func (u *udp) Do(ctx context.Context, req *Request) (*dns.Msg, error) {
	if req.Truncated {
		// If TC is set, the choice of records in the answer (if any)
		// do not really matter much as the client is supposed to
		// just discard the message and retry over TCP, anyway.
		//
		// https://serverfault.com/questions/991520/how-is-truncation-performed-in-dns-according-to-rfc-1035
		return tcpDo(ctx, u.addr, u.config, nil, req)
	}

	reqKey := udpCacheKey(req.ID, req.Question)

	var cancel context.CancelFunc = func() {}
	resp, ok, _ := u.sender.LoadOrCreate(reqKey, func() (*udpresp, error) {
		uctx, ucancel := context.WithCancel(ctx)
		cancel = ucancel
		return &udpresp{ctx: uctx, cancel: cancel}, nil
	})
	defer cancel()
	defer func() {
		if s := resp.session.Load(); s != nil {
			s.remove(resp)
		}
	}()
	if !ok {
		defer u.sender.CompareAndDelete(reqKey, resp)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-u.ctx.Done():
			return nil, u.ctx.Err()
		case u.wchan <- &udpPacket{ctx: ctx, question: req.Bytes(), response: resp}:
		}
	}

	select {
	case <-ctx.Done():
		if msg := resp.msg.Load(); msg != nil {
			return msg, nil
		}
		return nil, fmt.Errorf("ctx is canceled: %w", ctx.Err())
	case <-u.ctx.Done():
		return nil, fmt.Errorf("ctx udp resolver is canceled: %w", u.ctx.Err())
	case <-resp.ctx.Done():
		if msg := resp.msg.Load(); msg != nil {
			return msg, nil
		}
		if err := resp.failure.Load(); err != nil {
			return nil, fmt.Errorf("UDP query socket failed: %w", *err)
		}
		return nil, fmt.Errorf("response ctx is canceled: %w", resp.ctx.Err())
	}
}

func NewDoU(config Config) (Transport, error) {
	addr, err := ParseAddr("udp", config.Host, "53")
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	udp := &udp{
		config: config,
		addr:   addr,
		ctx:    ctx,
		cancel: cancel,
		wchan:  make(chan *udpPacket, 200),
		done:   make(chan struct{}),
	}
	if !addr.IsFqdn() {
		udp.staticAddr = net.UDPAddrFromAddrPort(addr.(netapi.IPAddress).AddrPort())
	}

	go udp.loopWrite()

	return udp, nil
}
