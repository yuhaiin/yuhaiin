package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"golang.zx2c4.com/wireguard/conn"
)

var _ conn.Endpoint = (*Endpoint)(nil)

type Endpoint netip.AddrPort

func (e Endpoint) ClearSrc()           {}
func (e Endpoint) SrcToString() string { return "" }
func (e Endpoint) DstToString() string { return (netip.AddrPort)(e).String() }
func (e Endpoint) DstToBytes() []byte  { return yerror.Ignore((netip.AddrPort)(e).MarshalBinary()) }
func (e Endpoint) DstIP() netip.Addr   { return (netip.AddrPort)(e).Addr() }
func (e Endpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type netBindClient struct {
	mu       sync.Mutex
	conn     net.PacketConn
	reserved []byte
}

func newNetBindClient(reserved []byte) *netBindClient { return &netBindClient{reserved: reserved} }

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

	ips, err := netapi.Bootstrap.LookupIP(context.TODO(), ipStr)
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
	return []conn.ReceiveFunc{bind.receive}, uport, nil
}

func (bind *netBindClient) Close() error {
	if bind.conn != nil {
		return bind.conn.Close()
	}
	return nil
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

	conn, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}

	bind.conn = conn

	return conn, nil
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

		addrPort, err = naddr.AddrPort(context.Background())
		if err != nil {
			return 0, err
		}
	}

	eps[0] = Endpoint(addrPort)
	if n > 3 {
		copy(packets[0][1:4], []byte{0, 0, 0})
	}
	sizes[0] = n

	return 1, nil
}

func (bind *netBindClient) Send(buffs [][]byte, endpoint conn.Endpoint) error {
	ep, ok := endpoint.(Endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	addr := netip.AddrPort(ep)

	conn, err := bind.connect()
	if err != nil {
		return err
	}

	for _, buff := range buffs {
		if len(buff) > 3 && len(bind.reserved) == 3 {
			copy(buff[1:], bind.reserved)
		}

		_, err = conn.WriteTo(buff, net.UDPAddrFromAddrPort(addr))
		if err != nil {
			return err
		}
	}

	return nil
}

func (bind *netBindClient) SetMark(mark uint32) error { return nil }
func (bind *netBindClient) BatchSize() int            { return 1 }
