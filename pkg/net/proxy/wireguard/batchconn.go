package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/tailscale/wireguard-go/conn"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	// This acts as a compile-time check for our usage of ipv6.Message in
	// batchingConn for both IPv6 and IPv4 operations.
	_ ipv6.Message = ipv4.Message{}
)

// batchingConn is a nettype.PacketConn that provides batched i/o.
type batchingConn interface {
	ReadBatch(msgs []ipv6.Message, flags int) (n int, err error)
	WriteBatch(buffs []ipv6.Message, flags int) (int, error)
}

type Batch struct {
	net.PacketConn
	conn batchingConn
	pool sync.Pool
}

func NewIPv6Batch(batchSize int, conn net.PacketConn) *Batch {
	c := ipv6.NewPacketConn(conn)

	return &Batch{
		PacketConn: conn,
		conn:       c,
		pool: sync.Pool{
			New: func() any {
				return make([]ipv6.Message, batchSize)
			},
		},
	}
}

func (b *Batch) WriteBatch(buf [][]byte, addr *net.UDPAddr) error {
	buffs := b.pool.Get().([]ipv6.Message)
	defer b.pool.Put(buffs)

	for i, b := range buf {
		buffs[i].Buffers = [][]byte{b}
		buffs[i].Addr = addr
		buffs[i].OOB = buffs[i].OOB[:0]
	}

	var head int
	for {
		n, err := b.conn.WriteBatch(buffs[head:len(buf)], 0)
		if err != nil || n == len(buffs[head:len(buf)]) {
			// Returning the number of packets written would require
			// unraveling individual msg len and gso size during a coalesced
			// write. The top of the call stack disregards partial success,
			// so keep this simple for now.
			return err
		}
		head += n
	}
}

func (b *Batch) ReadBatch(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
	msgs := b.pool.Get().([]ipv6.Message)
	defer b.pool.Put(msgs)

	for i, b := range bufs {
		msgs[i].Buffers = [][]byte{b}
		msgs[i].Addr = nil
		msgs[i].OOB = msgs[i].OOB[:0]
	}

	n, err = b.conn.ReadBatch(msgs[:len(bufs)], 0)
	if err != nil {
		return 0, err
	}

	for i, msg := range msgs[:n] {
		if msg.N == 0 {
			sizes[i] = 0
			continue
		}

		var addrPort netip.AddrPort
		uaddr, ok := msg.Addr.(*net.UDPAddr)
		if ok {
			addrPort = uaddr.AddrPort()
		} else {
			naddr, err := netapi.ParseSysAddr(msg.Addr)
			if err != nil {
				return 0, err
			}

			addrPort, err = dialer.ResolverAddrPort(context.Background(), naddr)
			if err != nil {
				return 0, err
			}
		}

		eps[i] = Endpoint(addrPort)
		sizes[i] = msg.N
	}

	return n, nil
}
