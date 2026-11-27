//go:build !android

package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"golang.org/x/sys/unix"
)

func TestConntrackGetEncodesReplyTuple(t *testing.T) {
	for _, tc := range []struct {
		name     string
		src, dst netip.AddrPort
		family   uint8
	}{
		{"ipv4", netip.MustParseAddrPort("203.0.113.1:22000"), netip.MustParseAddrPort("192.0.2.10:40000"), unix.AF_INET},
		{"ipv4-mapped", netip.MustParseAddrPort("[::ffff:203.0.113.1]:443"), netip.MustParseAddrPort("192.0.2.10:1"), unix.AF_INET},
		{"ipv6", netip.MustParseAddrPort("[2001:db8::1]:22000"), netip.MustParseAddrPort("[2001:db8:1::5]:51000"), unix.AF_INET6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := encodeConntrackGet(unix.IPPROTO_UDP, tc.src, tc.dst)
			if err != nil {
				t.Fatal(err)
			}
			if got := binary.NativeEndian.Uint32(b[0:4]); int(got) != len(b) {
				t.Fatalf("length %d, message %d", got, len(b))
			}
			if typ := binary.NativeEndian.Uint16(b[4:6]); typ != nfnlSubsysCTNetlink<<8|ipctnlMsgCTGet {
				t.Fatalf("type %#x", typ)
			}
			if b[unix.NLMSG_HDRLEN] != tc.family {
				t.Fatalf("family %d", b[unix.NLMSG_HDRLEN])
			}
			var src, dst netip.AddrPort
			ok := walkAttrs(b[unix.NLMSG_HDRLEN+nfGenMsgLen:], func(typ uint16, value []byte) {
				if typ == ctaTupleReply {
					src, dst, _ = parseConntrackTuple(value)
				}
			})
			want := func(a netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(a.Addr().Unmap(), a.Port()) }
			if !ok || src != want(tc.src) || dst != want(tc.dst) {
				t.Fatalf("reply tuple %s -> %s, ok=%v", src, dst, ok)
			}
		})
	}
	if _, err := encodeConntrackGet(unix.IPPROTO_TCP, netip.MustParseAddrPort("192.0.2.1:1"), netip.MustParseAddrPort("[2001:db8::1]:2")); err == nil {
		t.Fatal("mixed families were encoded")
	}
}

// conntrackReply builds the data of a CT_NEW message as the kernel sends it.
func conntrackReply(orig, reply [2]netip.AddrPort) []byte {
	tuple := func(b []byte, typ uint16, t [2]netip.AddrPort) []byte {
		srcType, dstType := uint16(ctaIPv6Src), uint16(ctaIPv6Dst)
		if t[0].Addr().Is4() {
			srcType, dstType = ctaIPv4Src, ctaIPv4Dst
		}
		start := len(b)
		b = appendAttrHeader(b, typ|nlaFNested)
		ip := len(b)
		b = appendAttrHeader(b, ctaTupleIP|nlaFNested)
		b = appendAttr(b, srcType, t[0].Addr().AsSlice())
		b = appendAttr(b, dstType, t[1].Addr().AsSlice())
		closeAttr(b, ip)
		proto := len(b)
		b = appendAttrHeader(b, ctaTupleProto|nlaFNested)
		b = appendAttr(b, ctaProtoNum, []byte{unix.IPPROTO_TCP})
		b = appendAttr(b, ctaProtoSrc, binary.BigEndian.AppendUint16(nil, t[0].Port()))
		b = appendAttr(b, ctaProtoDst, binary.BigEndian.AppendUint16(nil, t[1].Port()))
		closeAttr(b, proto)
		closeAttr(b, start)
		return b
	}
	b := []byte{unix.AF_INET, 0, 0, 0}
	b = appendAttr(b, 7, []byte{1, 2, 3, 4}) // CTA_STATUS precedes the tuples in real replies
	b = tuple(b, ctaTupleOrig, orig)
	b = tuple(b, ctaTupleReply, reply)
	return b
}

func TestParseConntrackOriginal(t *testing.T) {
	pod := netip.MustParseAddrPort("10.244.0.5:22000")
	remote := netip.MustParseAddrPort("203.0.113.1:22000")
	node := netip.MustParseAddrPort("192.0.2.10:61000")
	src, dst, ok := parseConntrackOriginal(conntrackReply([2]netip.AddrPort{pod, remote}, [2]netip.AddrPort{remote, node}))
	if !ok || src != pod || dst != remote {
		t.Fatalf("original %s -> %s ok=%v", src, dst, ok)
	}
	pod6 := netip.MustParseAddrPort("[fd00:244::5]:22000")
	remote6 := netip.MustParseAddrPort("[2406:da14:12:df00::1]:22000")
	node6 := netip.MustParseAddrPort("[2001:db8::10]:22000")
	src, dst, ok = parseConntrackOriginal(conntrackReply([2]netip.AddrPort{pod6, remote6}, [2]netip.AddrPort{remote6, node6}))
	if !ok || src != pod6 || dst != remote6 {
		t.Fatalf("original %s -> %s ok=%v", src, dst, ok)
	}
	for name, data := range map[string][]byte{
		"empty":     nil,
		"no tuple":  {unix.AF_INET, 0, 0, 0},
		"truncated": conntrackReply([2]netip.AddrPort{pod, remote}, [2]netip.AddrPort{remote, node})[:20],
	} {
		if _, _, ok := parseConntrackOriginal(data); ok {
			t.Errorf("%s: parsed a tuple", name)
		}
	}
}

func ifAddrMessage(attrs map[uint16]netip.Addr) []byte {
	b := make([]byte, unix.SizeofIfAddrmsg)
	for _, typ := range []uint16{unix.IFA_ADDRESS, unix.IFA_LOCAL} {
		if a, ok := attrs[typ]; ok {
			b = appendAttr(b, typ, a.AsSlice())
		}
	}
	return b
}

func TestParseIfAddr(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs map[uint16]netip.Addr
		want  netip.Addr
	}{
		{"ipv6", map[uint16]netip.Addr{unix.IFA_ADDRESS: netip.MustParseAddr("fd00:244::5")}, netip.MustParseAddr("fd00:244::5")},
		{"point-to-point", map[uint16]netip.Addr{
			unix.IFA_ADDRESS: netip.MustParseAddr("10.0.0.2"), unix.IFA_LOCAL: netip.MustParseAddr("10.0.0.1"),
		}, netip.MustParseAddr("10.0.0.1")},
		{"loopback", map[uint16]netip.Addr{unix.IFA_LOCAL: netip.MustParseAddr("127.0.0.1")}, netip.Addr{}},
		{"link-local", map[uint16]netip.Addr{unix.IFA_ADDRESS: netip.MustParseAddr("fe80::1")}, netip.Addr{}},
	} {
		got, ok := parseIfAddr(ifAddrMessage(tc.attrs))
		if ok != tc.want.IsValid() || (ok && got != tc.want) {
			t.Errorf("%s: %s %v", tc.name, got, ok)
		}
	}
	if _, ok := parseIfAddr([]byte{1, 2}); ok {
		t.Error("short message parsed")
	}
}

func TestParseNetNSLink(t *testing.T) {
	for link, want := range map[string]uint64{
		"net:[4026531840]": 4026531840, "net:[]": 0, "mnt:[4026531840]": 0, "net:[12": 0, "net:[0]": 0,
	} {
		if got, ok := parseNetNSLink([]byte(link)); got != want || ok != (want != 0) {
			t.Errorf("%q: %d %v", link, got, ok)
		}
	}
}

// fakeNS is a namespace whose sockets and addresses tests control.
type fakeNS struct {
	inode   uint64
	mu      sync.Mutex
	addrs   []netip.Addr
	sockets map[netip.AddrPort]netapi.Process
	closed  atomic.Bool
	dumps   atomic.Int64
}

func (f *fakeNS) FindProcessName(network string, local, remote netip.AddrPort) (netapi.Process, error) {
	if f.closed.Load() {
		return netapi.Process{}, errors.New("closed")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.sockets[local]; ok {
		return p, nil
	}
	return netapi.Process{}, errors.New("socket not found")
}

func (f *fakeNS) Close() error { f.closed.Store(true); return nil }

func (f *fakeNS) set(addrs []netip.Addr, sockets map[netip.AddrPort]netapi.Process) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs, f.sockets = addrs, sockets
}

func (f *fakeNS) netNS() *netNS {
	return &netNS{
		inode: f.inode,
		diag:  f,
		addrs: func() ([]netip.Addr, error) {
			f.dumps.Add(1)
			f.mu.Lock()
			defer f.mu.Unlock()
			return append([]netip.Addr(nil), f.addrs...), nil
		},
		close: f.Close,
	}
}

// fakeHost is a proc directory plus the namespaces its PIDs refer to.
type fakeHost struct {
	t        testing.TB
	proc     string
	clock    time.Time
	host     *fakeNS
	mu       sync.Mutex
	ns       map[uint64]*fakeNS
	denied   map[uint64]error
	opens    map[uint64]int
	rebuilds atomic.Int64
}

const fakeSelfInode = 1

func newFakeHost(t testing.TB, hostAddrs ...string) (*fakeHost, *netNSIndex) {
	h := &fakeHost{
		t: t, proc: t.TempDir(), clock: time.Unix(1000, 0),
		host: &fakeNS{inode: fakeSelfInode}, ns: map[uint64]*fakeNS{},
		denied: map[uint64]error{}, opens: map[uint64]int{},
	}
	for _, a := range hostAddrs {
		h.host.addrs = append(h.host.addrs, netip.MustParseAddr(a))
	}
	h.addPID(1, fakeSelfInode)
	x := newNetNSIndex(h.proc, fakeSelfInode, h.open, func() (*netNS, error) {
		h.rebuilds.Add(1)
		n := h.host.netNS()
		n.diag = nil
		return n, nil
	})
	x.now = func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.clock }
	t.Cleanup(func() { _ = x.Close() })
	return h, x
}

func (h *fakeHost) addPID(pid int, inode uint64) {
	dir := filepath.Join(h.proc, strconv.Itoa(pid), "ns")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Symlink(fmt.Sprintf("net:[%d]", inode), filepath.Join(dir, "net")); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) removePID(pid int) {
	if err := os.RemoveAll(filepath.Join(h.proc, strconv.Itoa(pid))); err != nil {
		h.t.Fatal(err)
	}
}

// pod adds a namespace with one process and the given address and sockets.
func (h *fakeHost) pod(pid int, inode uint64, addr string, sockets ...netip.AddrPort) *fakeNS {
	f := &fakeNS{inode: inode}
	procs := map[netip.AddrPort]netapi.Process{}
	for _, s := range sockets {
		procs[s] = netapi.Process{Path: fmt.Sprintf("/pod/%d", pid), Pid: uint(pid)}
	}
	f.set([]netip.Addr{netip.MustParseAddr(addr)}, procs)
	h.mu.Lock()
	h.ns[inode] = f
	h.mu.Unlock()
	h.addPID(pid, inode)
	return f
}

func (h *fakeHost) open(pid int, inode uint64) (*netNS, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.opens[inode]++
	if err := h.denied[inode]; err != nil {
		return nil, err
	}
	f, ok := h.ns[inode]
	if !ok {
		return nil, unix.ENOENT
	}
	return f.netNS(), nil
}

func (h *fakeHost) advance(d time.Duration) {
	h.mu.Lock()
	h.clock = h.clock.Add(d)
	h.mu.Unlock()
}

func (h *fakeHost) openCount(inode uint64) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.opens[inode]
}

var (
	podAddr    = netip.MustParseAddr("10.244.0.5")
	podSocket  = netip.AddrPortFrom(podAddr, 22000)
	remoteAddr = netip.MustParseAddrPort("203.0.113.1:22000")
)

func TestNetNSIndexClassifiesAddresses(t *testing.T) {
	h, x := newFakeHost(t, "192.0.2.10")
	h.pod(100, 500, "10.244.0.5", podSocket)

	if _, owned := x.containers(netip.MustParseAddr("192.0.2.10")); owned {
		t.Fatal("a host address was attributed to a container")
	}
	namespaces, owned := x.containers(podAddr)
	if !owned || len(namespaces) != 1 || namespaces[0].inode != 500 {
		t.Fatalf("pod address: %v %v", namespaces, owned)
	}
	for _, a := range []string{"127.0.0.1", "::1", "fe80::1", "0.0.0.0", "ff02::1"} {
		if _, owned := x.containers(netip.MustParseAddr(a)); owned {
			t.Errorf("%s is shared by every namespace but was attributed", a)
		}
	}
	// Unknown addresses (a LAN client, say) refresh at most once per interval.
	before := h.rebuilds.Load()
	for range 100 {
		if _, owned := x.containers(netip.MustParseAddr("192.168.1.50")); owned {
			t.Fatal("unknown address attributed")
		}
	}
	if h.host.dumps.Load() > 2 || before != 1 {
		t.Fatalf("host addresses dumped %d times", h.host.dumps.Load())
	}
	h.advance(2 * netNSRefreshInterval)
	h.pod(101, 501, "10.244.0.6")
	if _, owned := x.containers(netip.MustParseAddr("10.244.0.6")); !owned {
		t.Fatal("a new pod was not found after the interval")
	}
}

func TestNetNSIndexDeduplicatesNamespaces(t *testing.T) {
	h, x := newFakeHost(t)
	h.pod(100, 500, "10.244.0.5", podSocket)
	for pid := 101; pid < 110; pid++ {
		h.addPID(pid, 500) // more processes in the same pod
	}
	h.addPID(200, fakeSelfInode) // a host process
	if _, owned := x.containers(podAddr); !owned {
		t.Fatal("pod not indexed")
	}
	if n := h.openCount(500); n != 1 {
		t.Fatalf("namespace opened %d times", n)
	}
	if n := h.openCount(fakeSelfInode); n != 0 {
		t.Fatalf("host namespace opened as a container %d times", n)
	}
}

func TestNetNSIndexFindRejectsAmbiguousSockets(t *testing.T) {
	h, x := newFakeHost(t)
	a := h.pod(100, 500, "10.244.0.5", podSocket)
	b := h.pod(200, 600, "10.244.0.5") // the same address in a second namespace
	namespaces, owned := x.containers(podAddr)
	if !owned || len(namespaces) != 2 {
		t.Fatalf("namespaces %d owned %v", len(namespaces), owned)
	}
	p, err := x.find(namespaces, podAddr, "udp", podSocket, remoteAddr)
	if err != nil || p.Pid != 100 {
		t.Fatalf("only namespace A has the socket: %+v %v", p, err)
	}
	b.set(b.addrs, map[netip.AddrPort]netapi.Process{podSocket: {Pid: 200}})
	if p, err := x.find(namespaces, podAddr, "udp", podSocket, remoteAddr); err == nil {
		t.Fatalf("socket present in two namespaces was attributed to %+v", p)
	}
	_ = a
}

func TestNetNSIndexFollowsAddressToNewNamespace(t *testing.T) {
	h, x := newFakeHost(t)
	old := h.pod(100, 500, "10.244.0.5")
	namespaces, _ := x.containers(podAddr)
	// The pod is replaced: its namespace goes away and the address is reused.
	h.removePID(100)
	old.set(nil, nil)
	h.pod(200, 600, "10.244.0.5", podSocket)
	h.advance(2 * netNSRefreshInterval)
	p, err := x.find(namespaces, podAddr, "tcp", podSocket, remoteAddr)
	if err != nil || p.Pid != 200 {
		t.Fatalf("lookup after the address moved: %+v %v", p, err)
	}
	if !old.closed.Load() {
		t.Fatal("the namespace of the removed pod is still held open")
	}
}

func TestNetNSIndexRetriesOnlyTransientOpenErrors(t *testing.T) {
	h, x := newFakeHost(t)
	h.pod(100, 500, "10.244.0.5")
	h.pod(200, 600, "10.244.0.6")
	h.mu.Lock()
	h.denied[500] = unix.EPERM
	h.denied[600] = unix.ENOENT // the PID exited during the scan
	h.mu.Unlock()
	x.containers(netip.MustParseAddr("10.244.0.9"))
	h.mu.Lock()
	delete(h.denied, 500)
	delete(h.denied, 600)
	h.mu.Unlock()
	h.advance(2 * netNSRefreshInterval)
	if _, owned := x.containers(netip.MustParseAddr("10.244.0.6")); !owned {
		t.Fatal("a namespace that failed transiently was not retried")
	}
	if _, owned := x.containers(podAddr); owned || h.openCount(500) != 1 {
		t.Fatalf("a denied namespace was reopened %d times", h.openCount(500))
	}
}

func TestContainerProcessDumperRoutesBySourceAddress(t *testing.T) {
	h, x := newFakeHost(t, "192.0.2.10")
	h.pod(100, 500, "10.244.0.5", podSocket)
	var hostCalls atomic.Int64
	d := &ContainerProcessDumper{index: x, host: func(network string, src, dst netip.AddrPort) (netapi.Process, error) {
		hostCalls.Add(1)
		return netapi.Process{Path: "/host", Pid: 1}, nil
	}}
	p, err := d.FindProcessName("udp", podSocket, remoteAddr)
	if err != nil || p.Pid != 100 || hostCalls.Load() != 0 {
		t.Fatalf("pod flow: %+v %v host=%d", p, err, hostCalls.Load())
	}
	// A pod socket that is gone must not fall back to the host, where a
	// wildcard-bound UDP socket on the same port would match.
	if p, err := d.FindProcessName("udp", netip.AddrPortFrom(podAddr, 1), remoteAddr); err == nil || hostCalls.Load() != 0 {
		t.Fatalf("missing pod socket resolved to %+v", p)
	}
	for _, src := range []string{"192.0.2.10:5000", "192.168.1.50:5000", "[::ffff:192.0.2.10]:5000"} {
		if p, err := d.FindProcessName("tcp", netip.MustParseAddrPort(src), remoteAddr); err != nil || p.Pid != 1 {
			t.Fatalf("%s: %+v %v", src, p, err)
		}
	}
	if _, err := d.FindProcessName("icmp", podSocket, remoteAddr); err == nil {
		t.Fatal("invalid network accepted")
	}
}

func TestNetNSIndexConcurrentLookupsAndClose(t *testing.T) {
	h, x := newFakeHost(t)
	for i := range 20 {
		h.pod(100+i, uint64(500+i), fmt.Sprintf("10.244.0.%d", 10+i), netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 244, 0, byte(10 + i)}), 22000))
	}
	x.interval = 0
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 200 {
				addr := netip.AddrFrom4([4]byte{10, 244, 0, byte(10 + (i+j)%25)})
				if namespaces, owned := x.containers(addr); owned {
					_, _ = x.find(namespaces, addr, "tcp", netip.AddrPortFrom(addr, 22000), remoteAddr)
				}
			}
		})
	}
	time.Sleep(time.Millisecond)
	if err := x.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	h.mu.Lock()
	for inode, f := range h.ns {
		if h.opens[inode] > 0 && !f.closed.Load() {
			t.Errorf("namespace %d left open after Close", inode)
		}
	}
	h.mu.Unlock()
	if _, owned := x.containers(netip.MustParseAddr("10.244.0.10")); owned {
		t.Fatal("closed index still answers")
	}
}

// BenchmarkContainerProcessDumperRouting measures what the namespace index
// adds in front of the host lookup, which is stubbed out here.
func BenchmarkContainerProcessDumperRouting(b *testing.B) {
	h, x := newFakeHost(b, "192.0.2.10")
	h.pod(100, 500, "10.244.0.5", podSocket)
	d := &ContainerProcessDumper{index: x, host: func(string, netip.AddrPort, netip.AddrPort) (netapi.Process, error) {
		return netapi.Process{Pid: 1}, nil
	}}
	x.containers(podAddr) // populate
	for _, bc := range []struct {
		name string
		src  netip.AddrPort
	}{
		{"host-address", netip.MustParseAddrPort("192.0.2.10:5000")},
		{"loopback", netip.MustParseAddrPort("127.0.0.1:5000")},
		{"unknown-address-rate-limited", netip.MustParseAddrPort("192.168.1.50:5000")},
		{"pod-address", podSocket},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := d.FindProcessName("tcp", bc.src, remoteAddr); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkNetNSIndexRefresh measures one refresh with n namespaces of 10
// processes each, when nothing changed since the previous refresh.
func BenchmarkNetNSIndexRefresh(b *testing.B) {
	for _, n := range []int{10, 100, 500} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			h, x := newFakeHost(b)
			for i := range n {
				inode := uint64(1000 + i)
				h.pod(10000+i*10, inode, netip.AddrFrom4([4]byte{10, 244, byte(i >> 8), byte(i)}).String())
				for j := 1; j < 10; j++ {
					h.addPID(10000+i*10+j, inode)
				}
			}
			x.interval = 0
			x.containers(netip.MustParseAddr("10.0.0.1"))
			b.ReportAllocs()
			for b.Loop() {
				if !x.refresh(x.generation.Load()) {
					b.Fatal("refresh skipped")
				}
			}
		})
	}
}
