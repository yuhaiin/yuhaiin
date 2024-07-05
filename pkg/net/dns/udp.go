package dns

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

func init() {
	Register(pdns.Type_udp, NewDoU)
}

type udp struct {
	sf         singleflight.GroupSync[uint64, net.PacketConn]
	packetConn net.PacketConn
	*client
	sender syncmap.SyncMap[[2]byte, func([]byte)]
	mu     sync.RWMutex
}

func (u *udp) Close() error {
	if u.packetConn != nil {
		u.packetConn.Close()
		u.packetConn = nil
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

		if n < 2 {
			continue
		}

		send, ok := u.sender.Load([2]byte(buf[:2]))
		if !ok || send == nil {
			continue
		}

		send(buf[:n])
	}
}

func (u *udp) initPacketConn(ctx context.Context) (net.PacketConn, error) {
	if u.packetConn != nil {
		return u.packetConn, nil
	}

	conn, err, _ := u.sf.Do(0, func() (net.PacketConn, error) {
		if u.packetConn != nil {
			_ = u.packetConn.Close()
		}

		addr, err := ParseAddr("udp", u.config.Host, "53")
		if err != nil {
			return nil, fmt.Errorf("parse addr failed: %w", err)
		}

		conn, err := u.config.Dialer.PacketConn(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("get packetConn failed: %w", err)
		}

		u.mu.Lock()
		u.packetConn = conn
		u.mu.Unlock()

		go u.handleResponse(conn)
		return conn, nil
	})

	return conn, err
}

func NewDoU(config Config) (netapi.Resolver, error) {
	addr, err := ParseAddr("udp", config.Host, "53")
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}

	udp := &udp{}

	udp.client = NewClient(config, func(ctx context.Context, req *request) ([]byte, error) {
		if req.Truncated {
			// If TC is set, the choice of records in the answer (if any)
			// do not really matter much as the client is supposed to
			// just discard the message and retry over TCP, anyway.
			//
			// https://serverfault.com/questions/991520/how-is-truncation-performed-in-dns-according-to-rfc-1035
			return tcpDo(ctx, addr, config, nil, req)
		}

		packetConn, err := udp.initPacketConn(ctx)
		if err != nil {
			return nil, err
		}

		id := [2]byte{req.Question[0], req.Question[1]}

		respChan := make(chan []byte, 1)

		send := func(buf []byte) {
			b := pool.Clone(buf)
			select {
			case respChan <- b:
			case <-ctx.Done():
				pool.PutBytes(b)
			}
		}

		for {
			_, ok := udp.sender.LoadOrStore([2]byte(req.Question[:2]), send)
			if !ok {
				break
			}

			_, err = rand.Read(req.Question[0:2])
			if err != nil {
				return nil, err
			}
		}

		defer udp.sender.Delete([2]byte(req.Question[:2]))

		udpAddr, err := netapi.ResolveUDPAddr(ctx, addr)
		if err != nil {
			return nil, err
		}

		_, err = packetConn.WriteTo(req.Question, udpAddr)
		if err != nil {
			_ = packetConn.Close()
			return nil, err
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case data := <-respChan:
			data[0] = id[0]
			data[1] = id[1]
			return data, nil
		}
	})

	return udp, nil
}
