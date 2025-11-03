//go:build !android

package interfaces

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/vishvananda/netlink"
)

func defaultRoute() (d DefaultRouteDetails, err error) {
	v, err := defaultRouteInterfaceProcNet()
	if err == nil {
		d.InterfaceName = v
		return d, nil
	}
	// Issue 4038: the default route (such as on Unifi UDM Pro)
	// might be in a non-default table, so it won't show up in
	// /proc/net/route. Use netlink to find the default route.
	//
	// TODO(bradfitz): this allocates a fair bit. We should track
	// this in net/interfaces/monitor instead and have
	// interfaces.GetState take a netmon.Monitor or similar so the
	// routing table can be cached and the monitor's existing
	// subscription to route changes can update the cached state,
	// rather than querying the whole thing every time like
	// defaultRouteFromNetlink does.
	//
	// Then we should just always try to use the cached route
	// table from netlink every time, and only use /proc/net/route
	// as a fallback for weird environments where netlink might be
	// banned but /proc/net/route is emulated (e.g. stuff like
	// Cloud Run?).
	return defaultRouteFromNetlink()
}

func defaultRouteFromNetlink() (d DefaultRouteDetails, err error) {
	rms, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return d, fmt.Errorf("defaultRouteFromNetlink: List: %w", err)
	}
	for _, rm := range rms {
		fmt.Println(rm)
		if rm.Gw == nil {
			// A default route has a gateway. If it doesn't, skip it.
			continue
		}
		if rm.Dst != nil && !rm.Dst.IP.Equal(net.IPv4zero) && !rm.Dst.IP.Equal(net.IPv6zero) {
			// A default route has a nil destination to mean anything
			// so ignore any route for a specific destination.
			// TODO(bradfitz): better heuristic?
			// empirically this seems like enough.
			continue
		}
		// TODO(bradfitz): care about address family, if
		// callers ever start caring about v4-vs-v6 default
		// route differences.
		idx := int(rm.LinkIndex)
		if idx == 0 {
			continue
		}
		if iface, err := net.InterfaceByIndex(idx); err == nil {
			d.InterfaceName = iface.Name
			d.InterfaceIndex = idx
			return d, nil
		}
	}
	return d, errNoDefaultRoute
}

var zeroRouteBytes = []byte("00000000")
var procNetRoutePath = "/proc/net/route"

// maxProcNetRouteRead is the max number of lines to read from
// /proc/net/route looking for a default route.
const maxProcNetRouteRead = 1000

var errNoDefaultRoute = errors.New("no default route found")

func defaultRouteInterfaceProcNetInternal(bufsize int) (string, error) {
	f, err := os.Open(procNetRoutePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, bufsize)
	lineNum := 0
	for {
		lineNum++
		line, err := br.ReadSlice('\n')
		if err == io.EOF || lineNum > maxProcNetRouteRead {
			return "", errNoDefaultRoute
		}
		if err != nil {
			return "", err
		}
		if !bytes.Contains(line, zeroRouteBytes) {
			continue
		}
		fields := strings.Fields(string(line))
		ifc := fields[0]
		ip := fields[1]
		netmask := fields[7]

		if strings.HasPrefix(ifc, "tailscale") || strings.HasPrefix(ifc, "wg") || strings.HasPrefix(ifc, "tun") || strings.HasPrefix(ifc, "yuhaiin") {
			continue
		}
		if ip == "00000000" && netmask == "00000000" {
			// default route
			return ifc, nil // interface name
		}
	}
}

// returns string interface name and an error.
// io.EOF: full route table processed, no default route found.
// other io error: something went wrong reading the route file.
func defaultRouteInterfaceProcNet() (string, error) {
	rc, err := defaultRouteInterfaceProcNetInternal(128)
	if rc == "" && (errors.Is(err, io.EOF) || err == nil) {
		// https://github.com/google/gvisor/issues/5732
		// On a regular Linux kernel you can read the first 128 bytes of /proc/net/route,
		// then come back later to read the next 128 bytes and so on.
		//
		// In Google Cloud Run, where /proc/net/route comes from gVisor, you have to
		// read it all at once. If you read only the first few bytes then the second
		// read returns 0 bytes no matter how much originally appeared to be in the file.
		//
		// At the time of this writing (Mar 2021) Google Cloud Run has eth0 and eth1
		// with a 384 byte /proc/net/route. We allocate a large buffer to ensure we'll
		// read it all in one call.
		return defaultRouteInterfaceProcNetInternal(4096)
	}
	return rc, err
}

type monitor struct {
	ctx    context.Context
	cancel context.CancelFunc

	onRouteUpdate func(netlink.Route)
	onLinkUpdate  func(netlink.Link)
}

func NewMonitor(onRouteUpdate func(netlink.Route), onLinkUpdate func(netlink.Link)) NetworkMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	m := &monitor{
		ctx:           ctx,
		cancel:        cancel,
		onRouteUpdate: onRouteUpdate,
		onLinkUpdate:  onLinkUpdate,
	}

	if err := m.Start(); err != nil {
		log.Error("start monitor failed", "err", err)
	}

	return m
}

func (m *monitor) Start() error {
	go func() {
		var (
			routeCh  chan netlink.RouteUpdate
			routeLin chan netlink.LinkUpdate
		)

		routeSubscribe := func() {
			routeCh = make(chan netlink.RouteUpdate, 10)
			if err := netlink.RouteSubscribe(routeCh, m.ctx.Done()); err != nil {
				log.Error("subscribe route failed", "err", err)
				time.AfterFunc(time.Second*5, func() { close(routeCh) })
			}
		}

		linkSubscribe := func() {
			routeLin = make(chan netlink.LinkUpdate, 10)
			if err := netlink.LinkSubscribe(routeLin, m.ctx.Done()); err != nil {
				log.Error("subscribe link failed", "err", err)
				time.AfterFunc(time.Second*5, func() { close(routeLin) })
			}
		}

		routeSubscribe()
		linkSubscribe()

		for {
			select {
			case <-m.ctx.Done():
				return
			case msg, ok := <-routeCh:
				if !ok {
					log.Warn("check route listener is stopped, reconnect")
					routeSubscribe()
				} else {
					m.onRouteUpdate(msg.Route)
				}
			case msg, ok := <-routeLin:
				if !ok {
					log.Warn("check link listener is stopped, reconnect")
					linkSubscribe()
				} else {
					m.onLinkUpdate(msg.Link)
				}
			}
		}
	}()
	return nil
}

func (m *monitor) Stop() error {
	m.cancel()
	return nil
}

func startMonitor(onChange func(string)) NetworkMonitor {
	m := NewMonitor(
		func(r netlink.Route) {
			onChange("route")
		},
		func(l netlink.Link) {
			onChange("link")
		},
	)

	return m
}
