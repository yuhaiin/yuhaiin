package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

// fakeRoutes routes 192.168.20.0/24 via nic2, everything else via nic1, and
// 0.0.0.0/1 + 128.0.0.0/1 via our TUN (which selection must skip).
func fakeRoutes(t *testing.T, tun bool) {
	t.Helper()
	oldSelect, oldDefault, oldSkip, oldConfigured := selectRoute, defaultInterface, SkipInterface, ConfiguredInterface
	t.Cleanup(func() {
		selectRoute, defaultInterface, SkipInterface, ConfiguredInterface = oldSelect, oldDefault, oldSkip, oldConfigured
		SetSocketProtector(nil)
	})
	selectRoute = func(dst netip.Addr, exclude func(string) bool) (interfaces.RouteChoice, bool) {
		for _, r := range []struct{ p, iface string }{
			{"192.168.20.0/24", "nic2"}, {"0.0.0.0/1", "tun0"}, {"128.0.0.0/1", "tun0"}, {"0.0.0.0/0", "nic1"},
			{"fd20::/64", "nic2"}, {"::/0", "nic1"},
		} {
			p := netip.MustParsePrefix(r.p)
			if p.Contains(dst) && !exclude(r.iface) {
				return interfaces.RouteChoice{Interface: r.iface, Prefix: p}, true
			}
		}
		return interfaces.RouteChoice{}, false
	}
	defaultInterface = func() string { return "nic1" }
	SkipInterface = func() *set.Set[string] {
		s := set.NewSet[string]()
		if tun {
			s.Push("tun0")
		}
		return s
	}
	ConfiguredInterface = func() string { return "" }
}

func TestResolveEgress(t *testing.T) {
	mark := &SocketProtector{Method: "SO_MARK", Mark: 0x500, Protect: func(int32) error { return nil }}
	for _, tc := range []struct {
		name      string
		tun       bool
		mark      bool
		explicit  string
		dst       string
		want      string
		wantErr   bool
		platforms []string // empty: all
	}{
		{name: "no own TUN follows the OS", tun: false, dst: "8.8.8.8", want: "", platforms: []string{"darwin", "linux", "windows"}},
		{name: "explicit wins", tun: true, explicit: "nic2", dst: "8.8.8.8", want: "nic2"},
		{name: "explicit own TUN refused", tun: true, explicit: "tun0", dst: "8.8.8.8", wantErr: true},
		{name: "internet skips TUN", tun: true, dst: "8.8.8.8", want: "nic1", platforms: []string{"darwin", "windows"}},
		{name: "second LAN", tun: true, dst: "192.168.20.9", want: "nic2", platforms: []string{"darwin", "windows"}},
		{name: "IPv6 LAN", tun: true, dst: "fd20::9", want: "nic2", platforms: []string{"darwin", "windows"}},
		{name: "loopback never bound", tun: true, dst: "127.0.0.1", want: ""},
		{name: "link-local never bound", tun: true, dst: "fe80::1", want: ""},
		{name: "no destination takes default", tun: true, dst: "", want: "nic1", platforms: []string{"darwin", "windows"}},
		{name: "linux with mark is unbound", tun: true, mark: true, dst: "8.8.8.8", want: "", platforms: []string{"linux"}},
		{name: "linux without mark binds", tun: true, dst: "192.168.20.9", want: "nic2", platforms: []string{"linux"}},
		// Android: VpnService.protect alone keeps sockets out of the VPN,
		// whose TUN has no interface name, and routes are unreadable.
		{name: "android protected is unbound", tun: false, mark: true, dst: "8.8.8.8", want: "", platforms: []string{"android"}},
		{name: "android protected with TUN listed", tun: true, mark: true, dst: "8.8.8.8", want: "", platforms: []string{"android"}},
		{name: "android unprotected binds best-effort", tun: false, dst: "192.168.20.9", want: "nic2", platforms: []string{"android"}},
	} {
		platforms := tc.platforms
		if len(platforms) == 0 {
			platforms = []string{"darwin", "linux", "windows", "android"}
		}
		for _, platform := range platforms {
			t.Run(tc.name+"/"+platform, func(t *testing.T) {
				fakeRoutes(t, tc.tun)
				oldGOOS := goos
				goos = platform
				t.Cleanup(func() { goos = oldGOOS })
				if tc.mark {
					SetSocketProtector(mark)
				}
				var dst netip.Addr
				if tc.dst != "" {
					dst = netip.MustParseAddr(tc.dst)
				}
				got, err := resolveEgress(tc.explicit, dst, protectorTrusted())
				if (err != nil) != tc.wantErr || got != tc.want {
					t.Fatalf("resolveEgress = %q, %v; want %q (err %v)", got, err, tc.want, tc.wantErr)
				}
			})
		}
	}
}

// Android cannot read routes: without route data and with protect failing,
// a dial still proceeds (unbound) instead of failing with ErrNoEgress, which
// broke every outbound connection.
func TestResolveEgressAndroidWithoutRoutes(t *testing.T) {
	fakeRoutes(t, false)
	oldGOOS := goos
	goos = "android"
	t.Cleanup(func() { goos = oldGOOS })
	selectRoute = func(netip.Addr, func(string) bool) (interfaces.RouteChoice, bool) {
		return interfaces.RouteChoice{}, false
	}
	defaultInterface = func() string { return "" }
	for _, protected := range []bool{true, false} {
		if got, err := resolveEgress("", netip.MustParseAddr("2407:cdc0:8205::1"), protected); err != nil || got != "" {
			t.Fatalf("protected=%v: %q %v, want unbound without error", protected, got, err)
		}
	}
	if got, err := GetInterfaceByIP(netip.MustParseAddr("8.8.8.8").AsSlice()); err != nil || got != "" {
		t.Fatalf("ping egress = %q %v", got, err)
	}
	// An Android protector makes direct UDP a single socket, not per egress.
	SetSocketProtector(&SocketProtector{Method: "VpnService.protect", Protect: func(int32) error { return nil }})
	if perDestinationEgress(context.Background(), &Options{}) {
		t.Fatal("protected Android relay split per egress")
	}
}

// With our TUN up and the default route on it, nothing else can carry the
// destination: fail instead of looping.
func TestResolveEgressNoEgressFailsClosed(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux binds only without the mark; covered by the fallback test")
	}
	fakeRoutes(t, true)
	selectRoute = func(netip.Addr, func(string) bool) (interfaces.RouteChoice, bool) {
		return interfaces.RouteChoice{}, false
	}
	defaultInterface = func() string { return "tun0" }
	if _, err := resolveEgress("", netip.MustParseAddr("8.8.8.8"), false); !errors.Is(err, ErrNoEgress) {
		t.Fatalf("got %v, want ErrNoEgress", err)
	}
}

func TestProtectionReport(t *testing.T) {
	t.Cleanup(func() { SetSocketProtector(nil); SetProtectionUnavailable(nil) })
	SetProtectionUnavailable(&ProtectionUnavailable{Method: "SO_MARK", Mark: 0x500, Reason: "needs CAP_NET_ADMIN"})
	if r := Protection(); r.Installed || r.Unavailable == "" || r.Method != "SO_MARK" {
		t.Fatalf("unavailable report = %+v", r)
	}
	calls := 0
	SetSocketProtector(&SocketProtector{Method: "SO_MARK", Mark: 0x500, Protect: func(int32) error {
		calls++
		if calls == 2 {
			return errors.New("EPERM")
		}
		return nil
	}})
	if !protectorTrusted() {
		t.Fatal("fresh mark protector not trusted")
	}
	if ok, err := protectSocket(3); !ok || err != nil {
		t.Fatalf("protect = %v %v", ok, err)
	}
	if _, err := protectSocket(3); !errors.Is(err, ErrUnprotected) {
		t.Fatalf("failed protect = %v", err)
	}
	r := Protection()
	if r.Successes != 1 || r.Failures != 1 || r.LastError == "" {
		t.Fatalf("report = %+v", r)
	}
	if protectorTrusted() {
		t.Fatal("a failed mark must stop leaving sockets unbound")
	}
}

// fakePacketConn records what it sent and lets the test inject datagrams.
type fakePacketConn struct {
	iface  string
	local  net.Addr
	in     chan []byte
	mu     sync.Mutex
	sent   []string
	closed chan struct{}
	once   sync.Once
}

func newFakePacketConn(iface string, port int) *fakePacketConn {
	return &fakePacketConn{iface: iface, local: &net.UDPAddr{IP: net.IPv4zero, Port: port}, in: make(chan []byte, 4), closed: make(chan struct{})}
}

func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-f.in:
		return copy(b, p), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}, nil
	case <-f.closed:
		return 0, nil, net.ErrClosed
	}
}
func (f *fakePacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, a.String())
	return len(b), nil
}
func (f *fakePacketConn) Close() error                     { f.once.Do(func() { close(f.closed) }); return nil }
func (f *fakePacketConn) LocalAddr() net.Addr              { return f.local }
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestEgressPacketConnPerDestination(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("protected Linux sockets are not split per egress")
	}
	fakeRoutes(t, true)
	var mu sync.Mutex
	opened := map[string]*fakePacketConn{}
	listen := func(_ context.Context, _ string, opts *Options) (net.PacketConn, error) {
		mu.Lock()
		defer mu.Unlock()
		// The socket factory receives the egress already resolved.
		iface := opts.InterfaceName
		if _, dup := opened[iface]; dup {
			t.Errorf("second socket for %q", iface)
		}
		c := newFakePacketConn(iface, 40000+len(opened))
		opened[iface] = c
		return c, nil
	}
	c, err := newEgressPacketConn(context.Background(), "udp", Options{}, listen)
	if err != nil {
		t.Fatal(err)
	}
	for _, dst := range []string{"8.8.8.8:53", "192.168.20.9:53", "1.1.1.1:53", "192.168.20.10:53", "127.0.0.1:53"} {
		if _, err := c.WriteTo([]byte("q"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort(dst))); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	got := map[string][]string{}
	for iface, f := range opened {
		got[iface] = f.sent
	}
	mu.Unlock()
	want := map[string][]string{
		"nic1": {"8.8.8.8:53", "1.1.1.1:53"},
		"nic2": {"192.168.20.9:53", "192.168.20.10:53"},
		"":     {"127.0.0.1:53"},
	}
	for iface, w := range want {
		if !slices.Equal(got[iface], w) {
			t.Fatalf("egress %q sent %v, want %v (all: %v)", iface, got[iface], w, got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("sockets = %v", got)
	}

	// Replies on any egress arrive through the one conn.
	opened["nic2"].in <- []byte("from nic2")
	opened["nic1"].in <- []byte("from nic1")
	seen := map[string]bool{}
	buf := make([]byte, 64)
	for range 2 {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		seen[string(buf[:n])] = true
	}
	if !seen["from nic1"] || !seen["from nic2"] {
		t.Fatalf("replies = %v", seen)
	}

	// A read deadline is honored with no traffic.
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := c.ReadFrom(buf); !isTimeout(err) {
		t.Fatalf("idle read = %v, want timeout", err)
	}

	// A secondary egress that dies is dropped and reopened on next use.
	_ = opened["nic2"].Close()
	deadline := time.Now().Add(time.Second)
	for slices.Contains(c.Interfaces(), "nic2") {
		if time.Now().After(deadline) {
			t.Fatal("dead secondary socket kept")
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	delete(opened, "nic2")
	mu.Unlock()
	if _, err := c.WriteTo([]byte("q"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.168.20.9:53"))); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(c.Interfaces(), "nic2") {
		t.Fatal("secondary egress not reopened")
	}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadFrom(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after close = %v", err)
	}
}

// Concurrent writers to many egresses and a reader race nothing (go test -race).
func TestEgressPacketConnConcurrent(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("protected Linux sockets are not split per egress")
	}
	fakeRoutes(t, true)
	listen := func(_ context.Context, _ string, opts *Options) (net.PacketConn, error) {
		return newFakePacketConn(opts.InterfaceName, 1), nil
	}
	c, err := newEgressPacketConn(context.Background(), "udp", Options{}, listen)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			dst := "8.8.8.8:53"
			if i%2 == 0 {
				dst = "192.168.20.9:53"
			}
			for range 100 {
				if _, err := c.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort(dst))); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	go func() {
		buf := make([]byte, 8)
		for {
			if _, _, err := c.ReadFrom(buf); errors.Is(err, net.ErrClosed) {
				return
			}
		}
	}()
	wg.Wait()
	if n := len(c.Interfaces()); n != 2 {
		t.Fatalf("sockets = %v", c.Interfaces())
	}
	_ = c.Close()
}

// A socket for loopback peers follows no network: a default-network change
// must not close it (LAN Link peers on 127.0.0.1 went offline).
func TestLoopbackHintedSocketIsUntracked(t *testing.T) {
	m := netstate.NewManager()
	m.Apply(netstate.Snapshot{Selected: "en", Source: netstate.PlatformCallback, Networks: []netstate.Network{
		{ID: "en", Index: 2, Name: "en0", Available: true, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}}}, false)
	for _, tc := range []struct {
		untracked bool
		known     bool
	}{{false, true}, {true, false}} {
		raw, err := net.ListenUDP("udp4", &net.UDPAddr{})
		if err != nil {
			t.Fatal(err)
		}
		c, err := trackUDP(m, raw, &Options{untracked: tc.untracked}, netstate.Path{}, 4)
		if err != nil {
			t.Fatal(err)
		}
		if got := c.NetworkPath().Known(); got != tc.known {
			t.Fatalf("untracked=%v: path known = %v, want %v", tc.untracked, got, tc.known)
		}
		_ = c.Close()
	}

	// ListenPacket marks a loopback-hinted socket untracked.
	opts := &Options{PacketConnHintAddress: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:9"))}
	pc, err := ListenPacketWithOptions(context.Background(), "udp", "", opts)
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.Close()
	if !opts.untracked {
		t.Fatal("loopback-hinted socket not marked untracked")
	}
}

// Unbound sockets are tracked on the interface the OS routes them through,
// so a change of the default network does not end a flow on another NIC.
func TestPathInterface(t *testing.T) {
	fakeRoutes(t, true)
	for _, tc := range []struct{ bound, dst, want string }{
		{"nic2", "8.8.8.8", "nic2"},
		{"", "192.168.20.9", "nic2"},
		{"", "8.8.8.8", "nic1"},
		{"", "", "nic1"},
		{"", "127.0.0.1", "nic1"},
	} {
		var dst netip.Addr
		if tc.dst != "" {
			dst = netip.MustParseAddr(tc.dst)
		}
		if got := pathInterface(tc.bound, dst); got != tc.want {
			t.Errorf("pathInterface(%q, %s) = %q, want %q", tc.bound, tc.dst, got, tc.want)
		}
	}
	defaultInterface = func() string { return "tun0" }
	if got := pathInterface("", netip.Addr{}); got != "" {
		t.Errorf("own TUN as default tracked: %q", got)
	}
}
