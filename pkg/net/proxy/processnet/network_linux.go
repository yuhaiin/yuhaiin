//go:build linux && !android

// Package processnet connects isolated process networks to inbound routing.
package processnet

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweighttun"
	"github.com/yuhaiin/sessionnet"
)

// Link owns the duplicated TUN descriptor, packet stack and process lookup.
// The caller must keep the session alive and close Link after terminating it.
type Link struct {
	flows     io.Closer
	processes *netlink.NetNSProcessDumper
	once      sync.Once
	err       error
}

// Attach prepares routing before the caller releases the session's startup gate.
func Attach(owner *sessionnet.Session, handler netapi.Handler, addresses sessionnet.AddressConfig, mtu int, ipv6 bool, name string) (_ *Link, err error) {
	addresses, err = addresses.Resolve(ipv6)
	if err != nil {
		return nil, err
	}
	ns, err := os.Open("/proc/" + strconv.Itoa(owner.PID()) + "/ns/net")
	if err != nil {
		return nil, err
	}
	defer ns.Close()
	select {
	case <-owner.Done():
		return nil, errors.New("process network: namespace owner exited")
	default:
	}
	processes, err := netlink.NewNetNSProcessDumper(ns)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = processes.Close()
		}
	}()
	fd, err := owner.DupTun()
	if err != nil {
		return nil, err
	}
	ips := []netip.Addr{addresses.GatewayIPv4}
	prefixes := []netip.Prefix{netip.PrefixFrom(addresses.GatewayIPv4, 32)}
	if ipv6 {
		ips = append(ips, addresses.GatewayIPv6)
		prefixes = append(prefixes, netip.PrefixFrom(addresses.GatewayIPv6, 128))
	}
	if mtu == 0 {
		mtu = sessionnet.DefaultMTU
	}
	stack, err := lightweight.New(lightweight.Config{Addresses: ips, MTU: mtu, Promiscuous: true, ForwardUDP: true, Profile: lightweight.LocalTun}, &packets{fd})
	if err != nil {
		_ = fd.Close()
		return nil, err
	}
	flows, err := lightweighttun.NewFromStack(stack, &scopedHandler{Handler: handler, scope: processes}, prefixes, name)
	if err != nil {
		_ = stack.Close()
		return nil, err
	}
	return &Link{flows: flows, processes: processes}, nil
}

func (l *Link) Close() error {
	l.once.Do(func() { l.err = errors.Join(l.flows.Close(), l.processes.Close()) })
	return l.err
}

// CheckFakeIPOverlap rejects pools that shadow the isolated link or gateway.
func CheckFakeIPOverlap(addresses sessionnet.AddressConfig, pools [2]netip.Prefix, ipv6 bool) error {
	addresses, err := addresses.Resolve(ipv6)
	if err != nil {
		return err
	}
	links := []netip.Prefix{addresses.SessionIPv4}
	if ipv6 {
		links = append(links, addresses.SessionIPv6)
	}
	for _, pool := range pools {
		for _, link := range links {
			if pool.IsValid() && pool.Overlaps(link) {
				return fmt.Errorf("process network: link %s overlaps FakeIP pool %s", link, pool)
			}
		}
	}
	return nil
}

type scopedHandler struct {
	netapi.Handler
	scope netapi.ProcessDumper
}

func (h *scopedHandler) HandleStream(meta *netapi.StreamMeta) {
	meta.ProcessScope = h.scope
	h.Handler.HandleStream(meta)
}
func (h *scopedHandler) HandlePacket(packet *netapi.Packet) {
	packet.ProcessScope = h.scope
	h.Handler.HandlePacket(packet)
}

type packets struct{ *os.File }

func (p *packets) ReadPacket(b []byte) (int, error) { return p.Read(b) }
func (p *packets) WritePacket(b []byte) error {
	n, err := p.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}
