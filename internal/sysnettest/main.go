//go:build linux

// Command sysnettest drives the real System Network Manager inside the
// isolated Podman containers of scripts/integration/system-network-podman.sh.
// It must never run on a host network namespace.
//
//	sysnettest run DIR        apply DIR/config.json whenever it changes and
//	                          write DIR/status.json; SIGTERM cleans up
//	sysnettest serve ADDR NAME  TCP server answering "NAME <peer address>"
//	sysnettest probe ADDR     connect and print the answer
//	sysnettest nft-tables     list nftables tables
//	sysnettest nft-foreign    create a table owned by "another program"
package main

import (
	"bufio"
	"context"
	json "encoding/json/v2"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/maxminddb"
	sysnetmgr "github.com/Asutorufa/yuhaiin/pkg/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/forward"
	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// harnessConfig is written by the test script.
type harnessConfig struct {
	Version int                    `json:"version"`
	Tuns    []harnessTun           `json:"tuns"`
	TProxy  []sysnet.TProxyInbound `json:"tproxy"`
	GeoIP   string                 `json:"geoip"`
	Config  sysnet.Config          `json:"config"`
}

type harnessTun struct {
	ID        string   `json:"id"`
	Interface string   `json:"interface"`
	Required  []string `json:"required"`
}

type harnessStatus struct {
	Version    int               `json:"version"`
	Status     sysnet.Status     `json:"status"`
	Interfaces sysnet.Interfaces `json:"interfaces"`
	Error      string            `json:"error,omitzero"`
	Attached   map[string]int    `json:"attached"`
}

type inbounds struct{ cfg *harnessConfig }

func (i inbounds) TunInbounds(context.Context) []sysnet.TunInbound {
	var out []sysnet.TunInbound
	for _, t := range i.cfg.Tuns {
		out = append(out, sysnet.TunInbound{ID: t.ID, Name: "TUN " + t.ID})
	}
	return out
}

func (i inbounds) TProxyInbounds(context.Context) []sysnet.TProxyInbound { return i.cfg.TProxy }

type fileStore struct{ path string }

func (s fileStore) LoadSystemNetwork(context.Context) (sysnet.Config, error) {
	return sysnet.Config{}, nil
}
func (s fileStore) SaveSystemNetwork(_ context.Context, c sysnet.Config) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}

type geoSource struct{ db *maxminddb.MaxMindDB }

func (g *geoSource) PrefixesByCountries(c []string) ([]netip.Prefix, error) {
	if g.db == nil {
		return nil, fmt.Errorf("GeoIP database is not loaded")
	}
	return g.db.PrefixesByCountries(c)
}

func run(dir string) error {
	monitor := interfaces.StartNetworkMonitor()
	defer func() { _ = monitor.Close() }()
	routes, err := netlink.NewRouteManager()
	if err != nil {
		return err
	}
	geo := &geoSource{}
	cfg := &harnessConfig{}
	m := sysnetmgr.New(sysnetmgr.Options{Routes: routes, Forward: forward.New(), GeoIP: geo,
		Capabilities: sysnetmgr.PlatformCapabilities("linux", true, true)})
	m.SetInbounds(inbounds{cfg})
	if err := m.SetStore(context.Background(), fileStore{filepath.Join(dir, "saved.json")}); err != nil {
		return err
	}
	m.StartMonitor()

	var tproxy net.Listener
	attached := map[string]int{}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	var lastModified time.Time
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	writeStatus := func(version int, problem error) {
		list, _ := m.Interfaces(context.Background())
		s := harnessStatus{Version: version, Status: m.Status(), Interfaces: list, Attached: attached}
		if problem != nil {
			s.Error = problem.Error()
		}
		data, _ := json.Marshal(s)
		_ = os.WriteFile(filepath.Join(dir, "status.json.tmp"), data, 0o644)
		_ = os.Rename(filepath.Join(dir, "status.json.tmp"), filepath.Join(dir, "status.json"))
	}
	for {
		select {
		case <-signals:
			if tproxy != nil {
				_ = tproxy.Close()
			}
			for id := range attached {
				m.DetachTun(id)
			}
			err := m.Close()
			writeStatus(-1, err)
			return err
		case <-tick.C:
		}
		info, err := os.Stat(filepath.Join(dir, "config.json"))
		if err != nil || !info.ModTime().After(lastModified) {
			// Status follows reconciliation triggered by network changes.
			writeStatus(cfg.Version, nil)
			continue
		}
		lastModified = info.ModTime()
		data, err := os.ReadFile(filepath.Join(dir, "config.json"))
		if err != nil {
			continue
		}
		var next harnessConfig
		if err := json.Unmarshal(data, &next); err != nil {
			writeStatus(-2, err)
			continue
		}
		*cfg = next
		if cfg.GeoIP != "" && geo.db == nil {
			if db, err := maxminddb.NewMaxMindDB(cfg.GeoIP); err == nil {
				geo.db = db
			}
		}
		if len(cfg.TProxy) != 0 && tproxy == nil {
			if tproxy, err = transparentListener(cfg.TProxy[0].Listen); err != nil {
				writeStatus(cfg.Version, err)
				continue
			}
			go serveTProxy(tproxy)
		}
		// Detach TUNs no longer listed, then attach (or refresh) the rest.
		for id := range attached {
			if !slices.ContainsFunc(cfg.Tuns, func(t harnessTun) bool { return t.ID == id }) {
				m.DetachTun(id)
				delete(attached, id)
			}
		}
		var problem error
		for _, t := range cfg.Tuns {
			ifc, err := net.InterfaceByName(t.Interface)
			if err != nil {
				problem = err
				continue
			}
			a := sysnetmgr.TunAttachment{InboundID: t.ID, InboundName: "TUN " + t.ID, Interface: ifc.Name, Index: ifc.Index}
			addrs, _ := ifc.Addrs()
			for _, addr := range addrs {
				if n, ok := addr.(*net.IPNet); ok {
					ip, _ := netip.AddrFromSlice(n.IP)
					if ip.Unmap().Is4() {
						a.IPv4 = true
					} else if !ip.IsLinkLocalUnicast() {
						a.IPv6 = true
					}
				}
			}
			for _, p := range t.Required {
				a.Required = append(a.Required, netip.MustParsePrefix(p))
			}
			m.AttachTun(a)
			attached[t.ID] = ifc.Index
		}
		if _, err := m.Save(context.Background(), cfg.Config); err != nil {
			problem = err
		}
		writeStatus(cfg.Version, problem)
	}
}

// transparentListener accepts connections redirected by TProxy, like the
// tproxy inbound (IP_TRANSPARENT).
func transparentListener(address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			if serr == nil {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(context.Background(), "tcp", address)
}

func serveTProxy(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		// With TProxy the local address is the client's original destination.
		_, _ = fmt.Fprintf(c, "tproxy %s %s\n", c.LocalAddr(), c.RemoteAddr())
		_ = c.Close()
	}
}

func serve(address, name string) error {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		_, _ = fmt.Fprintf(c, "%s %s\n", name, host)
		_ = c.Close()
	}
}

func probe(address string) error {
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	fmt.Print(line)
	return nil
}

func nftTables() error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	var names []string
	for _, t := range tables {
		names = append(names, t.Name)
	}
	slices.Sort(names)
	fmt.Println(strings.Join(names, " "))
	return nil
}

func nftForeign() error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	table := conn.AddTable(&nftables.Table{Name: "other_app", Family: nftables.TableFamilyINet})
	accept := nftables.ChainPolicyAccept
	conn.AddChain(&nftables.Chain{Name: "forward", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &accept})
	return conn.Flush()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sysnettest run DIR | serve ADDR NAME | probe ADDR | nft-tables | nft-foreign")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = run(os.Args[2])
	case "serve":
		err = serve(os.Args[2], os.Args[3])
	case "probe":
		err = probe(os.Args[2])
	case "nft-tables":
		err = nftTables()
	case "nft-foreign":
		err = nftForeign()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
