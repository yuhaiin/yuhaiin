package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

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
	listenPacket func(context.Context, string, string, ...func(*dialer.Options)) (net.PacketConn, error)
	active       atomic.Pointer[bindSocket]
	stopped      atomic.Bool
	changed      func(*bindSocket)
	conn         net.PacketConn
	batchConn    *Batch

	openAddr atomic.Pointer[net.UDPAddr]
	reserved []byte
	mu       sync.Mutex
}

type bindSocket struct {
	conn    net.PacketConn
	batch   *Batch
	invalid atomic.Bool
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
		n.openAddr.Store(net.UDPAddrFromAddrPort(addrPort))
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := netapi.Bootstrap().LookupIP(ctx, ipStr)
	if err != nil {
		return nil, err
	}

	ip, ok := netip.AddrFromSlice(ips.PreferAAAA())
	if !ok {
		return nil, errors.New("failed to parse ip: " + ipStr)
	}

	n.openAddr.Store(net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), uint16(portNum))))

	return Endpoint(netip.AddrPortFrom(ip.Unmap(), uint16(portNum))), nil
}

// Open create a local udp listener
//
// because we don't read any wireguard config, so ignore the port here
// and we create udp listener by ourselves
func (bind *netBindClient) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	pc, err := bind.connect()
	if err != nil {
		return nil, 0, err
	}

	addr, err := netapi.ParseSysAddr(pc.LocalAddr())
	if err != nil {
		return nil, 0, err
	}

	if bind.BatchSize() > 1 {
		batch := bind.active.Load().batch
		return []conn.ReceiveFunc{func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
			return bind.receiveBatchFrom(batch, slab, packets)
		}}, addr.Port(), nil
	}

	return []conn.ReceiveFunc{func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		return bind.receiveFrom(pc, slab, packets)
	}}, addr.Port(), nil
}

func (bind *netBindClient) Close() error {
	bind.mu.Lock()
	old := bind.active.Swap(nil)
	if old != nil {
		bind.conn, bind.batchConn = nil, nil
	}
	bind.mu.Unlock()
	if old != nil {
		_ = old.conn.Close()
		if old.batch != nil {
			_ = old.batch.Close()
		}
	}
	return nil
}

func (bind *netBindClient) connectBatch() (*Batch, error) {
	_, err := bind.connect()
	if err != nil {
		return nil, err
	}

	state := bind.active.Load()
	if state == nil || state.batch == nil {
		return nil, fmt.Errorf("batch conn is nil")
	}

	return state.batch, nil
}

func (bind *netBindClient) connect() (net.PacketConn, error) {
	if bind.stopped.Load() {
		return nil, net.ErrClosed
	}
	if state := bind.active.Load(); state != nil {
		return state.conn, nil
	}

	bind.mu.Lock()
	defer bind.mu.Unlock()

	if bind.stopped.Load() {
		return nil, net.ErrClosed
	}
	if state := bind.active.Load(); state != nil {
		return state.conn, nil
	}

	state := &bindSocket{conn: bind.conn} // preconfigured transports in tests
	if state.conn == nil {
		listen := bind.listenPacket
		if listen == nil {
			listen = dialer.ListenPacket
		}
		pc, err := listen(context.TODO(), "udp", "", func(o *dialer.Options) {
			o.PacketConnHintAddress = bind.openAddr.Load()
			if bind.changed != nil {
				o.OnNetworkInvalidated = func() { bind.changed(state) }
			}
		})
		if err != nil {
			return nil, err
		}
		state.conn = pc
	}

	bind.conn = state.conn

	if bind.BatchSize() > 1 {
		state.batch = NewIPv6Batch(8, state.conn)
		bind.batchConn = state.batch
	}
	bind.active.Store(state)

	return bind.conn, nil
}

func (bind *netBindClient) receiveBatchFrom(batch *Batch, slab []byte, packets []conn.ReceivedPacket) (n int, err error) {

	bufs := make([][]byte, len(packets))
	sizes := make([]int, len(packets))
	eps := make([]conn.Endpoint, len(packets))
	packetSize := len(slab) / len(packets)
	for i := range bufs {
		bufs[i] = slab[i*packetSize : (i+1)*packetSize]
	}
	n, err = batch.ReadBatch(bufs, sizes, eps)
	for i := range n {
		packets[i] = conn.ReceivedPacket{Offset: i * packetSize, Size: sizes[i], Endpoint: eps[i]}
	}
	return n, err
}

func (bind *netBindClient) receive(slab []byte, packets []conn.ReceivedPacket) (n int, err error) {
	pc, err := bind.connect()
	if err != nil {
		return 0, err
	}
	return bind.receiveFrom(pc, slab, packets)
}

func (bind *netBindClient) receiveFrom(pc net.PacketConn, slab []byte, packets []conn.ReceivedPacket) (n int, err error) {

	n, addr, err := pc.ReadFrom(slab)
	if err != nil {
		return 0, err
	}

	addrPort, err := parseAddrPort(addr)
	if err != nil {
		return 0, err
	}

	if n > 3 {
		clear(slab[1:4])
	}

	packets[0] = conn.ReceivedPacket{Size: n, Endpoint: Endpoint(addrPort)}
	return 1, nil
}

func (bind *netBindClient) Send(buffs [][]byte, endpoint conn.Endpoint, offset int) error {
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
		buff = buff[offset:]
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
