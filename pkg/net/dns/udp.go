package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"golang.org/x/net/dns/dnsmessage"
)

func init() {
	Register(pdns.Type_udp, NewDoU)
}

type reqKey struct {
	ID       uint16
	Question dnsmessage.Question
}

type respBuf struct {
	done chan struct{}
	msg  dnsmessage.Message
	once sync.Once
}

func (r *respBuf) setMsg(msg dnsmessage.Message) {
	r.once.Do(func() {
		r.msg = msg
		close(r.done)
	})
}

type udp struct {
	packetConn    net.PacketConn
	addr          netapi.Address
	timer         *time.Timer
	sender        syncmap.SyncMap[reqKey, *respBuf]
	config        Config
	lastQueryTime atomic.Int64
	mu            sync.RWMutex
}

func (u *udp) Close() error {
	pc := u.packetConn
	if pc != nil {
		pc.Close()
		u.packetConn = nil
	}
	if u.timer != nil {
		u.timer.Stop()
	}
	return nil
}

func (u *udp) handleResponse(packet net.PacketConn) {
	defer func() {
		u.mu.Lock()
		u.packetConn = nil
		u.mu.Unlock()

		packet.Close()
	}()

	buf := pool.GetBytes(nat.MaxSegmentSize)
	defer pool.PutBytes(buf)

	for {
		n, _, err := packet.ReadFrom(buf)
		if err != nil {
			return
		}

		var msg dnsmessage.Message
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}

		send, ok := u.sender.Load(reqKey{
			ID:       msg.ID,
			Question: msg.Questions[0],
		})
		if !ok || send == nil {
			continue
		}

		send.setMsg(msg)
	}
}

func (u *udp) initPacketConn(ctx context.Context) (net.PacketConn, error) {
	u.mu.RLock()
	pc := u.packetConn
	u.mu.RUnlock()
	if pc != nil {
		u.lastQueryTime.Store(system.CheapNowNano())
		return pc, nil
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if u.packetConn != nil {
		return u.packetConn, nil
	}

	addr, err := ParseAddr("udp", u.config.Host, "53")
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}

	conn, err := u.config.Dialer.PacketConn(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("get packetConn failed: %w", err)
	}

	u.packetConn = conn

	go u.handleResponse(conn)

	u.timer = time.AfterFunc(time.Minute*10, func() {
		if time.Duration(system.CheapNowNano()-u.lastQueryTime.Load()) < time.Minute*10 {
			u.timer.Reset(time.Minute * 10)
		} else {
			u.mu.Lock()
			packet := u.packetConn
			u.packetConn = nil
			u.mu.Unlock()
			packet.Close()
		}
	})
	u.lastQueryTime.Store(system.CheapNowNano())

	return conn, nil
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

	packetConn, err := u.initPacketConn(ctx)
	if err != nil {
		return nil, err
	}

	reqKey := reqKey{
		ID:       req.ID,
		Question: req.Question,
	}

	respBuf, ok := u.sender.LoadOrStore(reqKey, &respBuf{done: make(chan struct{})})
	if !ok {
		defer u.sender.CompareAndDelete(reqKey, respBuf)

		udpAddr, err := dialer.ResolveUDPAddr(ctx, u.addr)
		if err != nil {
			return nil, err
		}

		_, err = packetConn.WriteTo(req.QuestionBytes, udpAddr)
		if err != nil {
			_ = packetConn.Close()
			return nil, err
		}
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-respBuf.done:
		return MsgResponse(respBuf.msg), nil
	}
}

func NewDoU(config Config) (Dialer, error) {
	addr, err := ParseAddr("udp", config.Host, "53")
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}

	udp := &udp{
		config: config,
		addr:   addr,
	}

	return udp, nil
}
