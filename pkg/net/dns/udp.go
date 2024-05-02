package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

func init() {
	Register(pdns.Type_udp, NewDoU)
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

	for {
		buf := pool.GetBytesBuffer(nat.MaxSegmentSize)
		n, _, err := buf.ReadFromPacket(packet)
		if err != nil {
			buf.Free()
			return
		}

		if n < 2 {
			buf.Free()
			continue
		}

		c, ok := u.bufChanMap.Load([2]byte(buf.Bytes()[:2]))
		if !ok || c == nil {
			buf.Free()
			continue
		}

		c.Send(buf)
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
	bufChan chan *pool.Bytes
}

func (b *bufChan) Send(buf *pool.Bytes) {
	select {
	case b.bufChan <- buf:
	case <-b.ctx.Done():
		buf.Free()
	}
}

func NewDoU(config Config) (netapi.Resolver, error) {
	addr, err := ParseAddr(statistic.Type_udp, config.Host, "53")
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}

	udp := &udp{}

	udp.client = NewClient(config, func(ctx context.Context, req []byte) (*pool.Bytes, error) {

		packetConn, err := udp.initPacketConn(ctx)
		if err != nil {
			return nil, err
		}
		id := [2]byte{req[0], req[1]}

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		bchan := &bufChan{bufChan: make(chan *pool.Bytes), ctx: ctx}

	_retry:
		_, ok := udp.bufChanMap.LoadOrStore([2]byte(req[:2]), bchan)
		if ok {
			binary.BigEndian.PutUint16(req[0:2], uint16(rand.UintN(math.MaxUint16)))
			goto _retry
		}
		defer udp.bufChanMap.Delete([2]byte(req[:2]))

		udpAddr := addr.UDPAddr(ctx)
		if udpAddr.Err != nil {
			return nil, udpAddr.Err
		}

		_, err = packetConn.WriteTo(req, udpAddr.V)
		if err != nil {
			_ = packetConn.Close()
			return nil, err
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case data := <-bchan.bufChan:
			data.Bytes()[0] = id[0]
			data.Bytes()[1] = id[1]
			return data, nil
		}
	})

	return udp, nil
}
