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
	"sync/atomic"
	"time"
	"unique"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/tailscale/wireguard-go/device"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type Wireguard struct {
	netapi.EmptyDispatch
	net    *netTun
	bind   *netBindClient
	conf   *protocol.Wireguard
	timer  *time.Timer
	device *device.Device

	happyDialer *dialer.HappyEyeballsv2Dialer[*gonet.TCPConn]

	count atomic.Int64

	idleTimeout time.Duration

	mu sync.Mutex
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(conf *protocol.Wireguard, p netapi.Proxy) (netapi.Proxy, error) {
	if conf.GetIdleTimeout() == 0 {
		conf.SetIdleTimeout(60 * 5)
	}
	if conf.GetIdleTimeout() <= 30 {
		conf.SetIdleTimeout(30)
	}

	w := &Wireguard{
		conf:        conf,
		idleTimeout: time.Duration(conf.GetIdleTimeout()) * time.Second * 2,
	}

	w.happyDialer = &dialer.HappyEyeballsv2Dialer[*gonet.TCPConn]{
		DialContext: func(ctx context.Context, ip net.IP, port uint16) (*gonet.TCPConn, error) {
			nt, err := w.initNet()
			if err != nil {
				return nil, err
			}
			return nt.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: int(port)})
		},
		Cache: lru.NewSyncLru(lru.WithCapacity[unique.Handle[string], net.IP](512)),
		Avg:   dialer.NewAvg(),
	}

	return w, nil
}

func (w *Wireguard) initNet() (*netTun, error) {
	net := w.net
	if net != nil {
		return net, nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.net != nil {
		return w.net, nil
	}

	dev, bind, net, err := makeVirtualTun(w.conf)
	if err != nil {
		return nil, err
	}

	w.device = dev
	w.net = net
	w.bind = bind

	if w.timer != nil {
		w.timer.Reset(w.idleTimeout)
	} else {
		w.timer = time.AfterFunc(w.idleTimeout, func() {
			if w.count.Load() > 0 {
				w.timer.Reset(w.idleTimeout)
			} else {
				w.mu.Lock()
				log.Debug("wireguard closing")
				if w.device != nil {
					w.device.Close()
					w.device = nil
				}

				if w.bind != nil {
					w.bind.Close()
					w.bind = nil
				}

				w.net = nil

				log.Debug("wireguard closed")
				w.mu.Unlock()
			}
		})
	}

	return net, nil
}

func (w *Wireguard) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	conn, err := w.happyDialer.DialHappyEyeballsv2(ctx, addr)
	if err != nil {
		return nil, err
	}

	w.count.Add(1)
	w.timer.Reset(w.idleTimeout)
	// net, err := w.initNet()
	// if err != nil {
	// 	return nil, err
	// }

	// addrPort, err := dialer.ResolveTCPAddr(ctx, addr)
	// if err != nil {
	// 	return nil, err
	// }

	// conn, err := net.DialContextTCP(ctx, addrPort)
	// if err != nil {
	// 	return nil, err
	// }

	// w.count.Add(1)
	// w.timer.Reset(w.idleTimeout)

	return &wrapGoNetTcpConn{wireguard: w, TCPConn: conn}, nil
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
	wireguard *Wireguard
	*gonet.TCPConn
	once sync.Once
}

func (w *wrapGoNetTcpConn) Close() error {
	w.once.Do(func() { w.wireguard.count.Add(-1) })
	return w.TCPConn.Close()
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
	wnet, err := w.initNet()
	if err != nil {
		return nil, err
	}

	goUC, err := wnet.DialUDP(nil, nil)
	if err != nil {
		return nil, err
	}

	w.count.Add(1)
	w.timer.Reset(w.idleTimeout)

	return &wrapGoNetUdpConn{
		wireguard: w,
		UDPConn:   goUC,
		ctx:       context.WithoutCancel(ctx),
	}, nil
}

type wrapGoNetUdpConn struct {
	wireguard *Wireguard
	*gonet.UDPConn
	ctx  context.Context
	once sync.Once
}

func (w *wrapGoNetUdpConn) Close() error {
	w.once.Do(func() { w.wireguard.count.Add(-1) })
	return w.UDPConn.Close()
}

func (w *wrapGoNetUdpConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	a, err := netapi.ParseSysAddr(addr)
	if err != nil {
		processErr(err)
		return 0, err
	}

	ur, err := dialer.ResolveUDPAddr(w.ctx, a)
	if err != nil {
		return 0, err
	}

	return w.UDPConn.WriteTo(buf, ur)
}

func (w *wrapGoNetUdpConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	n, addr, err := w.UDPConn.ReadFrom(buf)
	processErr(err)
	return n, addr, err
}

// creates a tun interface on netstack given a configuration
func makeVirtualTun(h *protocol.Wireguard) (*device.Device, *netBindClient, *netTun, error) {
	endpoints, err := parseEndpoints(h)
	if err != nil {
		return nil, nil, nil, err
	}
	tun, err := CreateNetTUN(endpoints, int(h.GetMtu()))
	if err != nil {
		return nil, nil, nil, err
	}

	bind := newNetBindClient(h.GetReserved())
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

	err = dev.IpcSetOperation(createIPCRequest(h))
	if err != nil {
		dev.Close()
		return nil, nil, nil, err
	}

	err = dev.Up()
	if err != nil {
		dev.Close()
		return nil, nil, nil, err
	}

	return dev, bind, tun, nil
}

func base64ToHex(s string) string {
	data, _ := base64.StdEncoding.DecodeString(s)
	return hex.EncodeToString(data)
}

// serialize the config into an IPC request
func createIPCRequest(conf *protocol.Wireguard) *bytes.Buffer {
	request := bytes.NewBuffer(nil)

	request.WriteString(fmt.Sprintf("private_key=%s\n", base64ToHex(conf.GetSecretKey())))

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
