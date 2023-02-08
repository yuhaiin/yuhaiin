package nat

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var MaxSegmentSize = (1 << 16) - 1

func NewTable(dialer proxy.Proxy) *Table {
	return &Table{dialer: dialer}
}

type Table struct {
	dialer proxy.Proxy
	cache  syncmap.SyncMap[string, net.PacketConn]
	lock   syncmap.SyncMap[string, *sync.Cond]
}

func (u *Table) write(pkt *Packet, key string) (bool, error) {
	dstpconn, ok := u.cache.Load(key)
	if !ok {
		return false, nil
	}

	_, err := dstpconn.WriteTo(pkt.Payload, pkt.dstAddr())
	dstpconn.SetReadDeadline(time.Now().Add(time.Minute))
	return true, err
}

type Packet struct {
	SourceAddress      net.Addr
	DestinationAddress proxy.Address
	dstUDPAddr         *net.UDPAddr
	WriteBack          func(b []byte, addr net.Addr) (int, error)
	Payload            []byte
}

func (p Packet) dstAddr() net.Addr {
	if p.dstUDPAddr != nil {
		return p.dstUDPAddr
	}

	return p.DestinationAddress
}

func (u *Table) Write(pkt *Packet) error {
	key := pkt.SourceAddress.String()

	ok, err := u.write(pkt, key)
	if err != nil {
		return fmt.Errorf("client to proxy failed: %w", err)
	}
	if ok {
		log.Verboseln("nat table use **old** udp addr write to:", pkt.DestinationAddress, "from", pkt.SourceAddress)
		return nil
	}

	log.Verboseln("nat table write to:", pkt.DestinationAddress, "from", pkt.SourceAddress)

	cond, ok := u.lock.LoadOrStore(key, sync.NewCond(&sync.Mutex{}))
	if ok {
		cond.L.Lock()
		cond.Wait()
		_, err := u.write(pkt, key)
		cond.L.Unlock()
		return err
	}

	defer u.lock.Delete(key)
	defer cond.Broadcast()

	pkt.DestinationAddress.WithValue(proxy.SourceKey{}, pkt.SourceAddress)
	pkt.DestinationAddress.WithValue(proxy.DestinationKey{}, pkt.DestinationAddress)

	dstpconn, err := u.dialer.PacketConn(pkt.DestinationAddress)
	if err != nil {
		return fmt.Errorf("dial %s failed: %w", pkt.DestinationAddress, err)
	}

	if really, ok := pkt.DestinationAddress.Value(proxy.CurrentKey{}); ok {
		pkt.dstUDPAddr, err = really.(proxy.Address).UDPAddr()
	} else {
		pkt.dstUDPAddr, err = pkt.DestinationAddress.UDPAddr()
	}

	if err != nil {
		return fmt.Errorf("get udp addr failed: %w", err)
	}
	u.cache.Store(key, dstpconn)

	if _, err = u.write(pkt, key); err != nil {
		return fmt.Errorf("write data to remote failed: %w", err)
	}

	pkt.Payload = nil

	go func() {
		defer func() {
			dstpconn.Close()
			u.cache.Delete(key)
		}()
		if err := u.writeBack(pkt, dstpconn); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Errorln("remote to local failed:", err)
		}
	}()

	return nil
}

func (u *Table) writeBack(pkt *Packet, dstpconn net.PacketConn) error {
	data := pool.GetBytes(MaxSegmentSize)
	defer pool.PutBytes(data)

	var dstAddr string
	if pkt.dstUDPAddr != nil {
		dstAddr = pkt.dstUDPAddr.AddrPort().Addr().String()
	}
	for {
		dstpconn.SetReadDeadline(time.Now().Add(time.Minute))
		n, from, err := dstpconn.ReadFrom(data)
		if err != nil {
			if ne, ok := err.(net.Error); (ok && ne.Timeout()) || errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
				return nil /* ignore I/O timeout & EOF */
			}

			return fmt.Errorf("read from proxy failed: %w", err)
		}

		log.Verboseln("nat table read data length:", n, "from", from, "dst:", pkt.dstAddr(), "fakeIP:", pkt.DestinationAddress, "maybe write to:", pkt.SourceAddress)

		fromAddr, err := proxy.ParseSysAddr(from)
		if err != nil {
			return err
		}

		if dstAddr == fromAddr.Hostname() {
			fromAddr = fromAddr.OverrideHostname(pkt.DestinationAddress.Hostname())
		}

		// write back to client with source address
		if _, err := pkt.WriteBack(data[:n], fromAddr); err != nil {
			return fmt.Errorf("write back to client failed: %w", err)
		}
	}
}

func (u *Table) Close() error {
	u.cache.Range(func(_ string, value net.PacketConn) bool {
		value.Close()
		return true
	})

	return nil
}
