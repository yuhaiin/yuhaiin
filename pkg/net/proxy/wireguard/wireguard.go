/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 */

package wireguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type netTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	incomingPacket chan *buffer.View
	mtu            int
	hasV4, hasV6   bool
}

type Net netTun

func base64ToHex(s string) string {
	data, _ := base64.StdEncoding.DecodeString(s)
	return hex.EncodeToString(data)
}

func CreateNetTUN(localAddresses []netip.Prefix, mtu int) (tun.Device, *Net, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	}
	dev := &netTun{
		ep:             channel.New(1024, uint32(mtu), ""),
		stack:          stack.New(opts),
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View),
		mtu:            mtu,
	}

	dev.ep.AddNotify(dev)
	tcpipErr := dev.stack.CreateNIC(1, dev.ep)
	if tcpipErr != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}
	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Addr().Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Addr().Is6() {
			protoNumber = ipv6.ProtocolNumber
		}

		protoAddr := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(ip.Addr().Unmap().AsSlice()),
				PrefixLen: ip.Bits(),
			},
			Protocol: protoNumber,
		}

		tcpipErr := dev.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{})
		if tcpipErr != nil {
			return nil, nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, tcpipErr)
		}
		if ip.Addr().Is4() {
			dev.hasV4 = true
		} else if ip.Addr().Is6() {
			dev.hasV6 = true
		}
	}
	if dev.hasV4 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if dev.hasV6 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}

	dev.events <- tun.EventUp
	return dev, (*Net)(dev), nil
}

// convert endpoint string to netip.Addr
func parseEndpoints(conf *protocol.Wireguard) ([]netip.Prefix, error) {
	endpoints := make([]netip.Prefix, 0, len(conf.Endpoint))
	for _, str := range conf.Endpoint {
		// var addr netip.Addr
		if strings.Contains(str, "/") {
			prefix, err := netip.ParsePrefix(str)
			if err != nil {
				return nil, err
			}
			endpoints = append(endpoints, prefix)
		} else {
			var err error
			addr, err := netip.ParseAddr(str)
			if err != nil {
				return nil, err
			}

			if addr.Is4() {
				endpoints = append(endpoints, netip.PrefixFrom(addr, 32))
			} else {
				endpoints = append(endpoints, netip.PrefixFrom(addr, 128))
			}
		}
	}

	return endpoints, nil
}

func (tun *netTun) Name() (string, error) {
	return "go", nil
}

func (tun *netTun) File() *os.File {
	return nil
}

func (tun *netTun) Events() <-chan tun.Event {
	return tun.events
}

func (tun *netTun) BatchSize() int { return 1 }

func (tun *netTun) Read(buf [][]byte, size []int, offset int) (int, error) {
	view, ok := <-tun.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}

	var err error
	size[0], err = view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}

	return 1, nil
}

func (tun *netTun) Write(buffers [][]byte, offset int) (int, error) {
	amount := 0
	for _, buf := range buffers {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		amount++

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		var networkProtocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(packet) {
		case header.IPv4Version:
			networkProtocol = header.IPv4ProtocolNumber
		case header.IPv6Version:
			networkProtocol = header.IPv6ProtocolNumber
		}

		tun.ep.InjectInbound(networkProtocol, pkb)
	}

	return amount, nil
}

func (tun *netTun) WriteNotify() {
	pkt := tun.ep.Read()
	if pkt == nil {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	tun.incomingPacket <- view
}

func (tun *netTun) Flush() error {
	return nil
}

func (tun *netTun) Close() error {
	tun.stack.RemoveNIC(1)

	if tun.events != nil {
		close(tun.events)
	}

	tun.ep.Close()

	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}

	return nil
}

func (tun *netTun) MTU() (int, error) {
	return tun.mtu, nil
}

func convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().Unmap().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

func (net *Net) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
	fa, pn := convertToFullAddr(addr)
	return gonet.DialContextTCP(ctx, net.stack, fa, pn)
}

func (net *Net) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		return net.DialContextTCPAddrPort(ctx, netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ip, uint16(addr.Port)))
}

func (net *Net) DialTCPAddrPort(addr netip.AddrPort) (*gonet.TCPConn, error) {
	fa, pn := convertToFullAddr(addr)
	return gonet.DialTCP(net.stack, fa, pn)
}

func (net *Net) DialTCP(addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		return net.DialTCPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return net.DialTCPAddrPort(netip.AddrPortFrom(ip, uint16(addr.Port)))
}

func (net *Net) ListenTCPAddrPort(addr netip.AddrPort) (*gonet.TCPListener, error) {
	fa, pn := convertToFullAddr(addr)
	return gonet.ListenTCP(net.stack, fa, pn)
}

func (net *Net) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	if addr == nil {
		return net.ListenTCPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return net.ListenTCPAddrPort(netip.AddrPortFrom(ip, uint16(addr.Port)))
}

func (net *Net) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	var lfa, rfa *tcpip.FullAddress
	var pn tcpip.NetworkProtocolNumber
	if laddr.IsValid() || laddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddr(laddr)
		lfa = &addr
	}
	if raddr.IsValid() || raddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddr(raddr)
		rfa = &addr
	}
	return gonet.DialUDP(net.stack, lfa, rfa, pn)
}

func (net *Net) ListenUDPAddrPort(laddr netip.AddrPort) (*gonet.UDPConn, error) {
	return net.DialUDPAddrPort(laddr, netip.AddrPort{})
}

func (net *Net) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var la, ra netip.AddrPort
	if laddr != nil {
		ip, _ := netip.AddrFromSlice(laddr.IP)
		la = netip.AddrPortFrom(ip, uint16(laddr.Port))
	}
	if raddr != nil {
		ip, _ := netip.AddrFromSlice(raddr.IP)
		ra = netip.AddrPortFrom(ip, uint16(raddr.Port))
	}
	return net.DialUDPAddrPort(la, ra)
}

func (net *Net) ListenUDP(laddr *net.UDPAddr) (*gonet.UDPConn, error) {
	return net.DialUDP(laddr, nil)
}

func (n *Net) HasV4() bool {
	return n.hasV4
}

func (n *Net) HasV6() bool {
	return n.hasV6
}

func IsDomainName(s string) bool {
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}
	last := byte('.')
	nonNumeric := false
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			partlen++
		case c == '-':
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}
	return nonNumeric
}

type Wireguard struct {
	netapi.EmptyDispatch
	net *Net
}

func New(conf *protocol.Protocol_Wireguard) protocol.WrapProxy {
	return func(p netapi.Proxy) (netapi.Proxy, error) {
		net, err := makeVirtualTun(conf.Wireguard)
		if err != nil {
			return nil, err
		}

		return &Wireguard{net: net}, nil
	}
}

func (w *Wireguard) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	addrPort, err := addr.AddrPort(ctx)
	if err != nil {
		return nil, err
	}
	return w.net.DialContextTCPAddrPort(ctx, addrPort)
}

func (w *Wireguard) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	addrPort, err := addr.AddrPort(ctx)
	if err != nil {
		return nil, err
	}

	goUC, err := w.net.DialUDPAddrPort(netip.AddrPort{}, addrPort)
	if err != nil {
		return nil, err
	}

	return &wrapGoNetUdpConn{ctx: ctx, UDPConn: goUC}, nil
}

type wrapGoNetUdpConn struct {
	ctx context.Context
	*gonet.UDPConn
}

func (w *wrapGoNetUdpConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	ad, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, err
	}

	uaddr, err := ad.UDPAddr(w.ctx)
	if err != nil {
		return 0, err
	}

	return w.UDPConn.WriteTo(buf, uaddr)
}

// creates a tun interface on netstack given a configuration
func makeVirtualTun(h *protocol.Wireguard) (*Net, error) {
	endpoints, err := parseEndpoints(h)
	if err != nil {
		return nil, err
	}
	tun, tnet, err := CreateNetTUN(endpoints, int(h.Mtu))
	if err != nil {
		return nil, err
	}

	// dev := device.NewDevice(tun, conn.NewDefaultBind(), nil /* device.NewLogger(device.LogLevelVerbose, "") */)
	dev := device.NewDevice(
		tun,
		&netBindClient{
			workers:  int(h.GetNumWorkers()),
			reserved: h.GetReserved(),
		},
		&device.Logger{
			Verbosef: func(format string, args ...any) {
				log.Debug(fmt.Sprintf(format, args...))
			},
			Errorf: func(format string, args ...any) {
				log.Error(fmt.Sprintf(format, args...))
			},
		})

	err = dev.IpcSet(createIPCRequest(h))
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	return tnet, nil
}

// serialize the config into an IPC request
func createIPCRequest(conf *protocol.Wireguard) string {
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", base64ToHex(conf.SecretKey)))

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf("public_key=%s\nendpoint=%s\n", base64ToHex(peer.PublicKey), peer.Endpoint))
		if peer.KeepAlive != 0 {
			request.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.KeepAlive))
		}
		if peer.PreSharedKey != "" {
			request.WriteString(fmt.Sprintf("preshared_key=%s\n", base64ToHex(peer.PreSharedKey)))
		}

		for _, ip := range peer.AllowedIps {
			request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip))
		}
	}

	return request.String()[:request.Len()]
}

type netBindClient struct {
	workers   int
	reserved  []byte
	readQueue chan *netReadInfo
}

func (n *netBindClient) ParseEndpoint(s string) (conn.Endpoint, error) {
	ipStr, port, _, err := splitAddrPort(s)
	if err != nil {
		return nil, err
	}

	var addr net.IP
	if IsDomainName(ipStr) {
		ips, err := netapi.Bootstrap.LookupIP(context.TODO(), ipStr)
		if err != nil {
			return nil, err
		}
		addr = ips[0]
	} else {
		addr = net.ParseIP(ipStr)
	}
	if addr == nil {
		return nil, errors.New("failed to parse ip: " + ipStr)
	}

	ip, _ := netip.AddrFromSlice(addr)

	return &netEndpoint{dst: netip.AddrPortFrom(ip.Unmap(), port)}, nil
}

func (bind *netBindClient) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	// log.Info(fmt.Sprintf("open port %d", uport))

	bind.readQueue = make(chan *netReadInfo)

	fun := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (cap int, err error) {
		r := &netReadInfo{
			buff: packets[0],
		}

		r.waiter.Add(1)
		bind.readQueue <- r
		r.waiter.Wait() // wait read goroutine done, or we will miss the result

		sizes[0] = r.bytes
		eps[0] = r.endpoint
		return 1, r.err
	}

	workers := bind.workers
	if workers <= 0 {
		workers = 1
	}
	arr := make([]conn.ReceiveFunc, workers)
	for i := 0; i < workers; i++ {
		arr[i] = fun
	}

	return arr, 0, nil
}

func (bind *netBindClient) Close() error {
	if bind.readQueue != nil {
		close(bind.readQueue)
	}
	return nil
}

func (bind *netBindClient) connectTo(endpoint *netEndpoint) error {
	endpoint.lock.Lock()
	defer endpoint.lock.Unlock()

	if endpoint.conn != nil {
		return nil
	}

	c, err := dialer.DialContext(context.Background(), "udp", endpoint.dst.String())
	if err != nil {
		return err
	}
	endpoint.conn = c

	go func(readQueue <-chan *netReadInfo, endpoint *netEndpoint) {
		for {
			v, ok := <-readQueue
			if !ok {
				return
			}

			go func() {
				i, err := c.Read(v.buff)

				if i > 3 {
					v.buff[1] = 0
					v.buff[2] = 0
					v.buff[3] = 0
				}

				v.bytes = i
				v.endpoint = endpoint
				v.err = err
				v.waiter.Done()
				if err != nil && errors.Is(err, io.EOF) {
					endpoint.lock.Lock()
					endpoint.conn = nil
					endpoint.lock.Unlock()
					return
				}
			}()
		}
	}(bind.readQueue, endpoint)

	return nil
}

func (bind *netBindClient) Send(buffs [][]byte, endpoint conn.Endpoint) error {
	var err error

	// log.Info(fmt.Sprintf("send to %s", endpoint.DstToString()))

	nend, ok := endpoint.(*netEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	conn := nend.conn

	if conn == nil {
	_retry:
		err = bind.connectTo(nend)
		if err != nil {
			return err
		}
		if conn = nend.conn; conn == nil {
			goto _retry
		}
	}

	for _, buff := range buffs {
		if len(buff) > 3 && len(bind.reserved) == 3 {
			copy(buff[1:], bind.reserved)
		}

		_, err = conn.Write(buff)
		if err != nil {
			return err
		}
	}

	return nil
}

func (bind *netBindClient) SetMark(mark uint32) error { return nil }
func (bind *netBindClient) BatchSize() int            { return 1 }

type netEndpoint struct {
	lock sync.Mutex
	dst  netip.AddrPort
	conn net.Conn
}

func (*netEndpoint) ClearSrc()           {}
func (e *netEndpoint) DstIP() netip.Addr { return e.dst.Addr() }
func (e *netEndpoint) SrcIP() netip.Addr { return netip.Addr{} }
func (e *netEndpoint) DstToBytes() []byte {
	var dat []byte
	if e.dst.Addr().Is4() {
		dat = e.dst.Addr().Unmap().AsSlice()
	} else {
		dat = e.dst.Addr().AsSlice()
	}
	dat = append(dat, byte(e.dst.Port()), byte(e.dst.Port()>>8))
	return dat
}
func (e *netEndpoint) DstToString() string { return e.dst.String() }
func (e *netEndpoint) SrcToString() string { return "" }

type netReadInfo struct {
	// status
	waiter sync.WaitGroup
	// param
	buff []byte
	// result
	bytes    int
	endpoint conn.Endpoint
	err      error
}

func splitAddrPort(s string) (ip string, port uint16, v6 bool, err error) {
	i := stringsLastIndexByte(s, ':')
	if i == -1 {
		return "", 0, false, errors.New("not an ip:port")
	}

	ip = s[:i]
	portStr := s[i+1:]
	if len(ip) == 0 {
		return "", 0, false, errors.New("no IP")
	}
	if len(portStr) == 0 {
		return "", 0, false, errors.New("no port")
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, false, errors.New("invalid port " + strconv.Quote(portStr) + " parsing " + strconv.Quote(s))
	}
	port = uint16(port64)
	if ip[0] == '[' {
		if len(ip) < 2 || ip[len(ip)-1] != ']' {
			return "", 0, false, errors.New("missing ]")
		}
		ip = ip[1 : len(ip)-1]
		v6 = true
	}

	return ip, port, v6, nil
}

func stringsLastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
