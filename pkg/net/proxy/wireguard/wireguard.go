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

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/tailscale/wireguard-go/device"
)

type Wireguard struct {
	netapi.EmptyDispatch
	net    *LightweightNetTun
	bind   *netBindClient
	conf   Config
	device *device.Device

	happyDialer *dialer.HappyEyeballsv2Dialer[net.Conn]
	once        sync.Once
}

func init() {
	register.RegisterContractPoint("wireguard", func(config contractnode.Wireguard, p netapi.Proxy) (netapi.Proxy, error) {
		return NewClient(wireguardConfigFromContract(config), p)
	})
}

func wireguardConfigFromContract(config contractnode.Wireguard) Config {
	return Config{
		SecretKey: config.SecretKey,
		Endpoint:  config.Endpoint,
		Peers:     wireguardPeersFromContract(config.Peers),
		MTU:       config.MTU,
		Reserved:  config.Reserved,
	}
}

func wireguardPeersFromContract(in []contractnode.WireguardPeer) []PeerConfig {
	out := make([]PeerConfig, 0, len(in))
	for _, peer := range in {
		out = append(out, PeerConfig{
			PublicKey:    peer.PublicKey,
			PreSharedKey: peer.PreSharedKey,
			Endpoint:     peer.Endpoint,
			KeepAlive:    peer.KeepAlive,
			AllowedIPs:   peer.AllowedIPs,
		})
	}
	return out
}

type Config struct {
	SecretKey string       `json:"secretKey"`
	Endpoint  []string     `json:"endpoint,omitzero"`
	Peers     []PeerConfig `json:"peers,omitzero"`
	MTU       int32        `json:"mtu,omitzero"`
	Reserved  []byte       `json:"reserved,omitzero"`
}

type PeerConfig struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitzero"`
	Endpoint     string   `json:"endpoint"`
	KeepAlive    int32    `json:"keepAlive,omitzero"`
	AllowedIPs   []string `json:"allowedIps,omitzero"`
}

func NewClient(conf Config, p netapi.Proxy) (netapi.Proxy, error) {
	endpoints, err := ParseEndpoints(conf.Endpoint)
	if err != nil {
		return nil, err
	}

	tun, err := CreateLightweightNetTUN(endpoints, int(conf.MTU))
	if err != nil {
		return nil, err
	}

	w := &Wireguard{
		conf: conf,
		net:  tun,
		bind: newNetBindClient(conf.Reserved),
		happyDialer: dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context, ip net.IP, port uint16) (net.Conn, error) {
			return tun.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: int(port)})
		}, dialer.WithHappyEyeballsSemaphore[net.Conn](semaphore.NewEmptySemaphore())),
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

	return conn, nil
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

type udpConn interface {
	net.Conn
	net.PacketConn
}

type wrapGoNetUdpConn struct {
	udpConn
	ctx        context.Context
	udpAddrMap syncmap.SyncMap[string, *net.UDPAddr]
}

func NewWrapGoNetUdpConn(ctx context.Context, conn udpConn) *wrapGoNetUdpConn {
	return &wrapGoNetUdpConn{udpConn: conn, ctx: ctx}
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

	n, err := w.udpConn.WriteTo(buf, udpAddr)
	if err != nil {
		return n, err
	}

	return n, nil
}

func (w *wrapGoNetUdpConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	n, addr, err := w.udpConn.ReadFrom(buf)
	processErr(err)
	return n, addr, err
}

// creates a tun interface on netstack given a configuration
func makeVirtualTun(h Config, bind *netBindClient, tun *LightweightNetTun) (*device.Device, error) {
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
func createIPCRequest(conf Config) *bytes.Buffer {
	request := bytes.NewBuffer(nil)

	fmt.Fprintf(request, "private_key=%s\n", base64ToHex(conf.SecretKey))

	for _, peer := range conf.Peers {
		fmt.Fprintf(request, "public_key=%s\nendpoint=%s\n", base64ToHex(peer.PublicKey), peer.Endpoint)
		if peer.KeepAlive != 0 {
			fmt.Fprintf(request, "persistent_keepalive_interval=%d\n", peer.KeepAlive)
		}
		if peer.PreSharedKey != "" {
			fmt.Fprintf(request, "preshared_key=%s\n", base64ToHex(peer.PreSharedKey))
		}

		for _, ip := range peer.AllowedIPs {
			fmt.Fprintf(request, "allowed_ip=%s\n", ip)
		}
	}

	return request
}
