package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/tailscale/wireguard-go/conn"
)

var _ conn.Endpoint = (*Endpoint)(nil)

type Endpoint netip.AddrPort

func (e Endpoint) ClearSrc()           {}
func (e Endpoint) SrcToString() string { return "" }
func (e Endpoint) DstToString() string { return (netip.AddrPort)(e).String() }
func (e Endpoint) DstToBytes() []byte {
	data, _ := (netip.AddrPort)(e).MarshalBinary()
	return data
}
func (e Endpoint) DstIP() netip.Addr { return (netip.AddrPort)(e).Addr() }
func (e Endpoint) SrcIP() netip.Addr { return netip.Addr{} }

type netBindClient struct {
	conn      net.PacketConn
	batchConn *Batch
	reserved  []byte
	mu        sync.Mutex
}

func newNetBindClient(reserved []byte) *netBindClient {
	nbc := &netBindClient{
		reserved: reserved,
	}

	return nbc
}

func (n *netBindClient) ParseEndpoint(s string) (conn.Endpoint, error) {
	addrPort, err := netip.ParseAddrPort(s)
	if err == nil {
		return Endpoint(addrPort), nil
	}

	ipStr, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}

	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}

	ips, err := dialer.Bootstrap.LookupIP(context.TODO(), ipStr)
	if err != nil {
		return nil, err
	}

	ip, ok := netip.AddrFromSlice(ips[0])
	if !ok {
		return nil, errors.New("failed to parse ip: " + ipStr)
	}

	return Endpoint(netip.AddrPortFrom(ip.Unmap(), uint16(portNum))), nil
}

func (bind *netBindClient) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	if bind.BatchSize() > 1 {
		return []conn.ReceiveFunc{bind.receiveBatch}, uport, nil
	}

	return []conn.ReceiveFunc{bind.receive}, uport, nil
}

func (bind *netBindClient) Close() error {
	if bind.conn != nil {
		_ = bind.conn.Close()
	}
	if bind.batchConn != nil {
		_ = bind.batchConn.Close()
	}
	return nil
}

func (bind *netBindClient) connectBatch() (*Batch, error) {
	_, err := bind.connect()
	if err != nil {
		return nil, err
	}

	bc := bind.batchConn
	if bc == nil {
		return nil, fmt.Errorf("batch conn is nil")
	}

	return bc, nil
}

func (bind *netBindClient) connect() (net.PacketConn, error) {
	conn := bind.conn
	if conn != nil {
		return conn, nil
	}

	bind.mu.Lock()
	defer bind.mu.Unlock()

	if bind.conn != nil {
		return bind.conn, nil
	}

	pc, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}

	bind.conn = pc

	if bind.BatchSize() > 1 {
		bind.batchConn = NewIPv6Batch(8, pc)
	}

	return bind.conn, nil
}

func (bind *netBindClient) receiveBatch(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
	conn, err := bind.connectBatch()
	if err != nil {
		return 0, err
	}

	return conn.ReadBatch(packets, sizes, eps)
}

func (bind *netBindClient) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
	conn, err := bind.connect()
	if err != nil {
		return 0, err
	}

	n, addr, err := conn.ReadFrom(packets[0])
	if err != nil {
		return 0, err
	}

	var addrPort netip.AddrPort
	uaddr, ok := addr.(*net.UDPAddr)
	if ok {
		addrPort = uaddr.AddrPort()
	} else {
		naddr, err := netapi.ParseSysAddr(addr)
		if err != nil {
			return 0, err
		}

		addrPort, err = dialer.ResolverAddrPort(context.Background(), naddr)
		if err != nil {
			return 0, err
		}
	}

	if n > 3 {
		copy(packets[0][1:4], []byte{0, 0, 0})
	}

	sizes[0] = n
	eps[0] = Endpoint(addrPort)

	return 1, nil
}

func (bind *netBindClient) Send(buffs [][]byte, endpoint conn.Endpoint) error {
	ep, ok := endpoint.(Endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	addr := netip.AddrPort(ep)

	uaddr := net.UDPAddrFromAddrPort(addr)

	if bind.BatchSize() > 1 {
		return bind.SendBatch(buffs, uaddr)
	}

	conn, err := bind.connect()
	if err != nil {
		return err
	}

	for _, buff := range buffs {
		if len(buff) > 3 && len(bind.reserved) == 3 {
			// the reserved only for cloudflare-warp
			copy(buff[1:], bind.reserved)
		}

		_, err = conn.WriteTo(buff, uaddr)
		if err != nil {
			return err
		}
	}

	return nil
}

func (bind *netBindClient) SendBatch(buffs [][]byte, addr *net.UDPAddr) error {
	conn, err := bind.connectBatch()
	if err != nil {
		return err
	}

	// when use writemmsg, the reserved will make can't connect
	// so current disabled
	//
	// if len(bind.reserved) == 3 {
	// 	for _, buff := range buffs {
	// 		if len(buff) > 3 {
	// 			buff[1] = bind.reserved[0]
	// 			buff[2] = bind.reserved[1]
	// 			buff[3] = bind.reserved[2]
	// 		}
	// 	}
	// }

	return conn.WriteBatch(buffs, addr)
}

func (bind *netBindClient) SetMark(mark uint32) error { return nil }
func (bind *netBindClient) BatchSize() int {
	// batch write seem have many problem
	// so current disabled
	//
	// if runtime.GOOS == "linux" {
	// 	return 8
	// }
	return 1
}
