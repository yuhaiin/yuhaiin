package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
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
	conn     *Batch
	reserved [3]byte
	mu       sync.Mutex
}

func newNetBindClient(reserved [3]byte) *netBindClient {
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

func (bind *netBindClient) connect() (*Batch, error) {
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

	bind.conn = NewIPv6Batch(bind.BatchSize(), pc)

	return bind.conn, nil
}

func (bind *netBindClient) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
	conn, err := bind.connect()
	if err != nil {
		return 0, err
	}

	return conn.ReadBatch(packets, sizes, eps)
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

	// when use writemmsg, the reserved will make can't connect
	// so current comment
	//
	// for _, buff := range buffs {
	// 	if len(buff) > 3 {
	// 		buff[1] = bind.reserved[0]
	// 		buff[2] = bind.reserved[1]
	// 		buff[3] = bind.reserved[2]
	// 	}
	// }

	return conn.WriteBatch(buffs, net.UDPAddrFromAddrPort(addr))
}

func (bind *netBindClient) SetMark(mark uint32) error { return nil }
func (bind *netBindClient) BatchSize() int {
	if runtime.GOOS == "linux" {
		return configuration.UDPBatchSize
	}
	return 1
}
