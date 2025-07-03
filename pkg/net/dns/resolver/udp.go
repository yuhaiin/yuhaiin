package resolver

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/miekg/dns"
)

func init() {
	Register(pdns.Type_udp, NewDoU)
}

func udpCacheKey(id uint16, question dns.Question) string {
	return fmt.Sprintf("%d:%s|%d", id, question.Name, question.Qtype)
}

type udpresp struct {
	done chan struct{}
	msg  dns.Msg
	once sync.Once
}

func (r *udpresp) setMsg(msg dns.Msg) {
	r.once.Do(func() {
		r.msg = msg
		close(r.done)
	})
}

type udp struct {
	packetConn    net.PacketConn
	addr          netapi.Address
	timer         *time.Timer
	sender        syncmap.SyncMap[string, *udpresp]
	config        Config
	lastQueryTime atomic.Int64
	mu            sync.RWMutex
	closed        atomic.Bool
}

func (u *udp) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.closed.Store(true)

	if u.packetConn != nil {
		u.packetConn.Close()
		u.packetConn = nil
	}

	if u.timer != nil {
		u.timer.Stop()
		u.timer = nil
	}

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

func (u *udp) initPacketConn(ctx context.Context) (net.PacketConn, error) {
	if u.closed.Load() {
		return nil, fmt.Errorf("udp resolver closed")
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed.Load() {
		return nil, fmt.Errorf("udp resolver closed")
	}

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

	go func() {
		defer func() {
			conn.Close()
			u.mu.Lock()
			u.packetConn = nil
			u.mu.Unlock()
		}()

		u.handleResponse(conn)
	}()

	u.timer = time.AfterFunc(time.Minute*10, u.checkIdleTimeout)

	return conn, nil
}

func (u *udp) checkIdleTimeout() {
	u.mu.Lock()
	defer u.mu.Unlock()

	if time.Duration(system.CheapNowNano()-u.lastQueryTime.Load()) < time.Minute*10 {
		if u.closed.Load() {
			return
		}

		if u.timer != nil {
			u.timer.Reset(time.Minute * 10)
		}
		return
	}

	if u.packetConn != nil {
		u.packetConn.Close()
		u.packetConn = nil
	}
}

func (u *udp) Write(ctx context.Context, p []byte) (err error) {
	packetConn, err := u.initPacketConn(ctx)
	if err != nil {
		return err
	}

	udpAddr, err := dialer.ResolveUDPAddr(ctx, u.addr)
	if err != nil {
		return err
	}

	_, err = packetConn.WriteTo(p, udpAddr)
	if err != nil {
		return err
	}

	u.lastQueryTime.Store(system.CheapNowNano())

	return nil
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

	resp, ok, _ := u.sender.LoadOrCreate(reqKey, func() (*udpresp, error) { return &udpresp{done: make(chan struct{})}, nil })
	if !ok {
		defer u.sender.CompareAndDelete(reqKey, resp)

		if err := u.Write(ctx, req.QuestionBytes); err != nil {
			return nil, err
		}
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-resp.done:
		return MsgResponse(resp.msg), nil
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
