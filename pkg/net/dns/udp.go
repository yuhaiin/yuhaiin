package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

func init() {
	Register(pdns.Type_udp, NewDoU)
	Register(pdns.Type_reserve, NewDoU)
}

type udp struct {
	*client
	bufChanMap syncmap.SyncMap[[2]byte, *bufChan]
	sf         singleflight.Group[uint64, net.PacketConn]
	packetConn net.PacketConn
	mu         sync.RWMutex
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

	buf := make([]byte, nat.MaxSegmentSize)
	for {
		n, _, err := packet.ReadFrom(buf)
		if err != nil {
			return
		}

		if n < 2 {
			continue
		}

		c, ok := u.bufChanMap.Load([2]byte(buf[:2]))
		if !ok {
			continue
		}

		c.Send(append([]byte(nil), buf[:n]...))
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

		addr, err := ParseAddr(statistic.Type_udp, u.config.Host, "53")
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

type bufChan struct {
	ctx     context.Context
	cancel  context.CancelFunc
	bufChan chan []byte
}

func (b *bufChan) Send(buf []byte) {
	select {
	case b.bufChan <- buf:
	case <-b.ctx.Done():
	}
}

func (b *bufChan) Close() { b.cancel() }

func NewDoU(config Config) (netapi.Resolver, error) {
	addr, err := ParseAddr(statistic.Type_udp, config.Host, "53")
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}

	udp := &udp{}

	udp.client = NewClient(config, func(ctx context.Context, req []byte) ([]byte, error) {

		packetConn, err := udp.initPacketConn(ctx)
		if err != nil {
			return nil, err
		}
		id := [2]byte{req[0], req[1]}

	_retry:
		_, ok := udp.bufChanMap.Load([2]byte(req[:2]))
		if ok {
			binary.BigEndian.PutUint16(req[0:2], uint16(rand.Intn(math.MaxUint16)))
			goto _retry
		}

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		bchan, _ := udp.bufChanMap.LoadOrStore([2]byte(req[:2]), &bufChan{bufChan: make(chan []byte), ctx: ctx, cancel: cancel})
		defer func() {
			udp.bufChanMap.Delete([2]byte(req[:2]))
			bchan.Close()
		}()

		udpAddr, err := addr.UDPAddr(ctx)
		if err != nil {
			return nil, err
		}

		_, err = packetConn.WriteTo(req, udpAddr)
		if err != nil {
			_ = packetConn.Close()
			return nil, err
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case data := <-bchan.bufChan:
			data[0] = id[0]
			data[1] = id[1]
			return data, nil
		}
	})

	return udp, nil
}
