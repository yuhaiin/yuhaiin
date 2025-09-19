package resolver

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/miekg/dns"
)

func init() {
	Register(pdns.Type_udp, NewDoU)
}

func udpCacheKey(id uint16, question dns.Question) string {
	return fmt.Sprintf("%d:%s|%d", id, question.Name, question.Qtype)
}

type udpresp struct {
	ctx    context.Context
	cancel context.CancelFunc
	msg    atomic.Pointer[dns.Msg]
}

func (r *udpresp) setMsg(msg dns.Msg) {
	r.cancel()
	r.msg.Store(&msg)
}

type udpPacket struct {
	question []byte
	ctx      context.Context
}

type udp struct {
	addr   netapi.Address
	sender syncmap.SyncMap[string, *udpresp]
	config Config

	ctx    context.Context
	cancel context.CancelFunc
	wchan  chan *udpPacket
}

func (u *udp) Close() error {
	u.cancel()
	return nil
}

func (u *udp) handleResponse(packet net.PacketConn) {
	buf := pool.GetBytes(nat.MaxSegmentSize)
	defer pool.PutBytes(buf)

	for {
		n, _, err := packet.ReadFrom(buf)
		if err != nil {
			return
		}

		msg, err := BytesResponse(buf[:n]).Msg()
		if err != nil {
			log.Warn("parse dns message failed", "err", err)
			continue
		}

		if len(msg.Question) == 0 {
			log.Warn("no question", "msg", msg)
			continue
		}

		send, ok := u.sender.Load(udpCacheKey(msg.Id, msg.Question[0]))
		if !ok || send == nil {
			continue
		}

		send.setMsg(msg)
	}
}

func (u *udp) loopWrite() {
	var mu sync.Mutex
	var packetConn net.PacketConn

	close := func() {
		mu.Lock()
		defer mu.Unlock()

		if packetConn != nil {
			packetConn.Close()
			packetConn = nil
		}
	}

	dial := func() (net.PacketConn, error) {
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

		packetConn, err = u.config.Dialer.PacketConn(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("get packetConn failed: %w", err)
		}

		go func() {
			defer close()
			u.handleResponse(packetConn)
		}()

		return packetConn, nil
	}

	for {
		select {
		case <-time.After(time.Minute * 10):
			close()

		case p := <-u.wchan:
			select {
			case <-p.ctx.Done():
				continue
			default:
			}

			pk, err := dial()
			if err != nil {
				log.Error("init packetConn failed", "err", err)
				continue
			}

			ctx, cancel := context.WithTimeout(u.ctx, configuration.ResolverTimeout)
			udpAddr, err := dialer.ResolveUDPAddr(ctx, u.addr)
			cancel()
			if err != nil {
				log.Error("resolve udp addr failed", "err", err)
				continue
			}

			pk.SetWriteDeadline(time.Now().Add(configuration.ResolverTimeout))
			_, err = pk.WriteTo(p.question, udpAddr)
			pk.SetWriteDeadline(time.Time{})
			if err != nil {
				log.Error("write to packetConn failed", "err", err)
				continue
			}

		case <-u.ctx.Done():
			return
		}
	}
}

func (u *udp) Do(ctx context.Context, req *Request) (Response, error) {
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
	defer cancel()

	resp, ok, _ := u.sender.LoadOrCreate(reqKey, func() (*udpresp, error) {
		uctx, ucancel := context.WithCancel(ctx)
		cancel = ucancel
		return &udpresp{ctx: uctx, cancel: cancel}, nil
	})
	if !ok {
		defer u.sender.CompareAndDelete(reqKey, resp)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-u.ctx.Done():
			return nil, u.ctx.Err()
		case u.wchan <- &udpPacket{req.QuestionBytes, ctx}:
		}
	}

	select {
	case <-ctx.Done():
		if msg := resp.msg.Load(); msg != nil {
			return MsgResponse(*msg), nil
		}
		return nil, ctx.Err()
	case <-u.ctx.Done():
		return nil, u.ctx.Err()
	case <-resp.ctx.Done():
		if msg := resp.msg.Load(); msg != nil {
			return MsgResponse(*msg), nil
		}
		return nil, resp.ctx.Err()
	}
}

func NewDoU(config Config) (Dialer, error) {
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
	}

	go udp.loopWrite()

	return udp, nil
}
