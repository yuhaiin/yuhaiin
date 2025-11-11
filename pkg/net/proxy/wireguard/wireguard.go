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
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/tailscale/wireguard-go/device"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type Wireguard struct {
	netapi.EmptyDispatch
	net    *NetTun
	once   sync.Once
	bind   *netBindClient
	conf   *node.Wireguard
	device *device.Device

	happyDialer *dialer.HappyEyeballsv2Dialer[*gonet.TCPConn]
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(conf *node.Wireguard, p netapi.Proxy) (netapi.Proxy, error) {
	endpoints, err := ParseEndpoints(conf.GetEndpoint())
	if err != nil {
		return nil, err
	}

	tun, err := CreateNetTUN(endpoints, int(conf.GetMtu()))
	if err != nil {
		return nil, err
	}

	w := &Wireguard{
		conf: conf,
		net:  tun,
		bind: newNetBindClient(conf.GetReserved()),
		happyDialer: dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context, ip net.IP, port uint16) (*gonet.TCPConn, error) {
			return tun.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: int(port)})
		}, dialer.WithHappyEyeballsSemaphore[*gonet.TCPConn](semaphore.NewEmptySemaphore())),
	}

	return w, nil
}

func (w *Wireguard) init() {
	w.once.Do(func() {
		dev, err := makeVirtualTun(w.conf, w.bind, w.net)
		if err != nil {
			log.Error("makeVirtualTun error", "error", err)
			return
		}

		w.device = dev
	})
}

func (w *Wireguard) Close() error {
	log.Debug("wireguard closing")
	device := w.device
	if device != nil {
		device.Close()
		w.device = nil
	}

	bind := w.bind
	if bind != nil {
		_ = bind.Close()
		w.bind = nil
	}

	net := w.net
	if net != nil {
		_ = net.Close()
		w.net = nil
	}

	log.Debug("wireguard closed")
	return nil
}

func (w *Wireguard) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	w.init()

	conn, err := w.happyDialer.DialHappyEyeballsv2(ctx, addr)
	if err != nil {
		return nil, err
	}

	return NewWrapGoNetTcpConn(conn), nil
}

func processErr(err error) {
	if err == nil {
		return
	}
	nerr, ok := err.(*net.OpError)
	if ok {
		if nerr.Timeout() {
			nerr.Err = os.ErrDeadlineExceeded
		}
	}
}

type wrapGoNetTcpConn struct {
	*gonet.TCPConn
}

func NewWrapGoNetTcpConn(conn *gonet.TCPConn) *wrapGoNetTcpConn {
	return &wrapGoNetTcpConn{TCPConn: conn}
}

func (w *wrapGoNetTcpConn) Read(b []byte) (int, error) {
	n, err := w.TCPConn.Read(b)
	processErr(err)
	return n, err
}

func (w *wrapGoNetTcpConn) Write(b []byte) (int, error) {
	n, err := w.TCPConn.Write(b)
	processErr(err)
	return n, err
}

func (w *Wireguard) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	w.init()

	goUC, err := w.net.DialUDP(nil, nil)
	if err != nil {
		return nil, err
	}

	return NewWrapGoNetUdpConn(context.WithoutCancel(ctx), goUC), nil
}

func (w *Wireguard) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	return 0, nil
}

type wrapGoNetUdpConn struct {
	*gonet.UDPConn
	ctx        context.Context
	udpAddrMap syncmap.SyncMap[string, *net.UDPAddr]
}

func NewWrapGoNetUdpConn(ctx context.Context, conn *gonet.UDPConn) *wrapGoNetUdpConn {
	return &wrapGoNetUdpConn{UDPConn: conn, ctx: ctx}
}

func (w *wrapGoNetUdpConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	a, err := netapi.ParseSysAddr(addr)
	if err != nil {
		processErr(err)
		return 0, err
	}

	var udpAddr *net.UDPAddr
	if !a.IsFqdn() {
		udpAddr = net.UDPAddrFromAddrPort(a.(netapi.IPAddress).AddrPort())
	} else {
		udpAddr, _, err = w.udpAddrMap.LoadOrCreate(addr.String(), func() (*net.UDPAddr, error) {
			ur, err := netapi.ResolverIP(w.ctx, a.Hostname())
			if err != nil {
				return nil, err
			}

			return ur.RandUDPAddr(a.Port()), nil
		})
		if err != nil {
			return 0, err
		}
	}

	n, err := w.UDPConn.WriteTo(buf, udpAddr)
	if err != nil {
		return n, err
	}

	return n, nil
}

func (w *wrapGoNetUdpConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	n, addr, err := w.UDPConn.ReadFrom(buf)
	processErr(err)
	return n, addr, err
}

// creates a tun interface on netstack given a configuration
func makeVirtualTun(h *node.Wireguard, bind *netBindClient, tun *NetTun) (*device.Device, error) {
	// dev := device.NewDevice(tun, conn.NewDefaultBind(), nil /* device.NewLogger(device.LogLevelVerbose, "") */)
	dev := device.NewDevice(
		tun,
		bind,
		&device.Logger{
			Verbosef: func(format string, args ...any) {
				_, file, line, _ := runtime.Caller(1)
				log.Debug(fmt.Sprintf(format, args...), "file", file, "line", line)
			},
			Errorf: func(format string, args ...any) {
				_, file, line, _ := runtime.Caller(1)
				log.Error(fmt.Sprintf(format, args...), "file", file, "line", line)
			},
		})

	// set wireguard config
	err := dev.IpcSetOperation(createIPCRequest(h))
	if err != nil {
		dev.Close()
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		dev.Close()
		return nil, err
	}

	return dev, nil
}

func base64ToHex(s string) string {
	data, _ := base64.StdEncoding.DecodeString(s)
	return hex.EncodeToString(data)
}

// serialize the config into an IPC request
func createIPCRequest(conf *node.Wireguard) *bytes.Buffer {
	request := bytes.NewBuffer(nil)

	fmt.Fprintf(request, "private_key=%s\n", base64ToHex(conf.GetSecretKey()))

	for _, peer := range conf.GetPeers() {
		fmt.Fprintf(request, "public_key=%s\nendpoint=%s\n", base64ToHex(peer.GetPublicKey()), peer.GetEndpoint())
		if peer.GetKeepAlive() != 0 {
			fmt.Fprintf(request, "persistent_keepalive_interval=%d\n", peer.GetKeepAlive())
		}
		if peer.GetPreSharedKey() != "" {
			fmt.Fprintf(request, "preshared_key=%s\n", base64ToHex(peer.GetPreSharedKey()))
		}

		for _, ip := range peer.GetAllowedIps() {
			fmt.Fprintf(request, "allowed_ip=%s\n", ip)
		}
	}

	return request
}
