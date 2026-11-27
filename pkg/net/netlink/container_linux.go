//go:build !android

package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"golang.org/x/sys/unix"
)

// ContainerProcessDumper resolves socket owners on the host and in the other
// network namespaces of the host, such as Kubernetes pods and containers.
//
// A flow is first mapped back through conntrack, which undoes the masquerade
// a CNI applies before a forwarded flow reaches a TUN device. The original
// source address then selects the namespace to search: an address of the
// host, or one no namespace owns (a LAN client, say), is looked up on the
// host as before; an address owned only by container namespaces is looked up
// only there. The host is never consulted for a container address, because a
// host UDP socket bound to the wildcard address would match any source.
type ContainerProcessDumper struct {
	host      func(network string, src, dst netip.AddrPort) (netapi.Process, error)
	conntrack atomic.Pointer[conntrackResolver]
	index     *netNSIndex
}

var _ netapi.ProcessDumper = (*ContainerProcessDumper)(nil)

// NewContainerProcessDumper returns a dumper for the namespaces visible in
// /proc. Entering other namespaces requires CAP_SYS_ADMIN and reading their
// links requires ptrace access; without them it behaves like
// [FindProcessName]. Conntrack is skipped when the kernel lacks it.
func NewContainerProcessDumper() (*ContainerProcessDumper, error) {
	self, err := netNSInode("/proc/thread-self/ns/net")
	if err != nil {
		if self, err = netNSInode("/proc/self/ns/net"); err != nil {
			return nil, err
		}
	}
	index := newNetNSIndex("/proc", self, openPIDNetNS("/proc"), openHostNetNS)
	d := &ContainerProcessDumper{host: FindProcessName, index: index}
	if ct, err := newConntrackResolver(); err == nil {
		d.conntrack.Store(ct)
	}
	return d, nil
}

// ProcessName implements [netapi.ProcessDumper].
func (d *ContainerProcessDumper) ProcessName(network string, src, dst netapi.Address) (netapi.Process, error) {
	ip, to, err := ProcessAddrs(src, dst)
	if err != nil {
		return netapi.Process{}, err
	}
	return d.FindProcessName(network, ip, to)
}

// FindProcessName resolves the owner of the flow observed as src -> dst.
func (d *ContainerProcessDumper) FindProcessName(network string, src, dst netip.AddrPort) (netapi.Process, error) {
	protocol, err := diagProtocol(network)
	if err != nil {
		return netapi.Process{}, err
	}
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	if ct := d.conntrack.Load(); ct != nil {
		osrc, odst, ok, err := ct.original(protocol, src, dst)
		switch {
		case ok:
			src, dst = osrc, odst
		case errors.Is(err, errConntrackUnavailable):
			if d.conntrack.CompareAndSwap(ct, nil) {
				_ = ct.Close()
			}
		}
	}
	if d.index != nil {
		if namespaces, owned := d.index.containers(src.Addr()); owned {
			return d.index.find(namespaces, src.Addr(), network, src, dst)
		}
	}
	return d.host(network, src, dst)
}

// Close releases every namespace socket after in-flight lookups complete.
func (d *ContainerProcessDumper) Close() error {
	var err error
	if ct := d.conntrack.Swap(nil); ct != nil {
		err = ct.Close()
	}
	if d.index != nil {
		err = errors.Join(err, d.index.Close())
	}
	return err
}

func diagProtocol(network string) (uint8, error) {
	if len(network) >= 3 {
		switch network[:3] {
		case "tcp":
			return unix.IPPROTO_TCP, nil
		case "udp":
			return unix.IPPROTO_UDP, nil
		}
	}
	return 0, fmt.Errorf("ErrInvalidNetwork: %s", network)
}

// processFinder is the part of [SockDiagProcessDumper] the index needs.
type processFinder interface {
	FindProcessName(network string, local, remote netip.AddrPort) (netapi.Process, error)
	Close() error
}

// netNS is one indexed namespace. Its sockets were created inside it, so they
// keep answering without setns; they also pin the namespace, so entries of
// namespaces no process uses any more are dropped on refresh.
type netNS struct {
	inode uint64
	diag  processFinder // nil for the host namespace
	addrs func() ([]netip.Addr, error)
	close func() error
}

// openNetNSFunc opens the network namespace of pid, which the scan found to
// have the given inode.
type openNetNSFunc func(pid int, inode uint64) (*netNS, error)

// netNSIndex maps addresses to the namespaces that own them. It is filled
// lazily: an unknown address triggers at most one refresh per interval.
type netNSIndex struct {
	proc     string
	self     uint64
	open     openNetNSFunc
	openHost func() (*netNS, error)
	interval time.Duration
	now      func() time.Time

	refreshMu   sync.Mutex
	lastRefresh time.Time
	generation  atomic.Uint64

	mu         sync.RWMutex
	host       *netNS
	namespaces map[uint64]*netNS
	failed     map[uint64]struct{}
	byAddr     map[netip.Addr][]*netNS
	hostAddrs  map[netip.Addr]struct{}
	closed     bool
}

const netNSRefreshInterval = time.Second

func newNetNSIndex(proc string, self uint64, open openNetNSFunc, openHost func() (*netNS, error)) *netNSIndex {
	return &netNSIndex{
		proc:       proc,
		self:       self,
		open:       open,
		openHost:   openHost,
		interval:   netNSRefreshInterval,
		now:        time.Now,
		namespaces: map[uint64]*netNS{},
		failed:     map[uint64]struct{}{},
	}
}

// containers reports the container namespaces owning addr, and whether addr
// belongs to container namespaces only. An unknown address refreshes the
// index first, subject to the refresh interval.
func (x *netNSIndex) containers(addr netip.Addr) ([]*netNS, bool) {
	if !indexableAddr(addr) {
		return nil, false
	}
	for attempt := 0; ; attempt++ {
		x.mu.RLock()
		generation := x.generation.Load()
		_, host := x.hostAddrs[addr]
		namespaces := x.byAddr[addr]
		x.mu.RUnlock()
		if host {
			return nil, false
		}
		if len(namespaces) != 0 {
			return namespaces, true
		}
		if attempt > 0 || !x.refresh(generation) {
			return nil, false
		}
	}
}

// find searches the namespaces owning addr. A socket found in more than one
// namespace is ambiguous and rejected rather than guessed. Missing sockets
// may mean addr moved to a new namespace, so the index is refreshed once.
func (x *netNSIndex) find(namespaces []*netNS, addr netip.Addr, network string, src, dst netip.AddrPort) (netapi.Process, error) {
	for attempt := 0; ; attempt++ {
		generation := x.generation.Load()
		var found netapi.Process
		matches := 0
		err := errors.New("socket not found in container namespaces")
		for _, ns := range namespaces {
			p, e := ns.diag.FindProcessName(network, src, dst)
			if e != nil {
				err = e
				continue
			}
			found = p
			matches++
		}
		switch {
		case matches == 1:
			return found, nil
		case matches > 1:
			return netapi.Process{}, fmt.Errorf("socket %s -> %s found in %d network namespaces", src, dst, matches)
		}
		if attempt > 0 || !x.refresh(generation) {
			return netapi.Process{}, err
		}
		var owned bool
		if namespaces, owned = x.lookup(addr); !owned {
			return netapi.Process{}, err
		}
	}
}

func (x *netNSIndex) lookup(addr netip.Addr) ([]*netNS, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	if _, host := x.hostAddrs[addr]; host {
		return nil, false
	}
	namespaces := x.byAddr[addr]
	return namespaces, len(namespaces) != 0
}

// refresh rebuilds the index unless another caller already did so after
// generation was observed. It reports whether the index may have changed.
func (x *netNSIndex) refresh(generation uint64) bool {
	x.refreshMu.Lock()
	defer x.refreshMu.Unlock()
	if x.generation.Load() != generation {
		return true
	}
	now := x.now()
	if !x.lastRefresh.IsZero() && now.Sub(x.lastRefresh) < x.interval {
		return false
	}
	x.lastRefresh = now
	if err := x.rebuild(); err != nil {
		return false
	}
	x.generation.Add(1)
	return true
}

// rebuild scans /proc for namespaces, opens new ones, drops unused ones and
// reloads every address list. It runs under refreshMu; lookups keep using
// the previous index until the new one is published.
func (x *netNSIndex) rebuild() error {
	x.mu.RLock()
	closed := x.closed
	host := x.host
	known := make(map[uint64]*netNS, len(x.namespaces))
	for inode, ns := range x.namespaces {
		known[inode] = ns
	}
	failed := make(map[uint64]struct{}, len(x.failed))
	for inode := range x.failed {
		failed[inode] = struct{}{}
	}
	x.mu.RUnlock()
	if closed {
		return errNetNSIndexClosed
	}
	if host == nil {
		var err error
		if host, err = x.openHost(); err != nil {
			return err
		}
		x.mu.Lock()
		x.host = host
		x.mu.Unlock()
	}

	seen, err := x.scan()
	if err != nil {
		return err
	}
	next := make(map[uint64]*netNS, len(seen))
	var stale []*netNS
	for inode, ns := range known {
		if _, ok := seen[inode]; ok {
			next[inode] = ns
		} else {
			stale = append(stale, ns)
		}
	}
	for inode := range failed {
		if _, ok := seen[inode]; !ok {
			delete(failed, inode)
		}
	}
	for inode, pid := range seen {
		if _, ok := next[inode]; ok {
			continue
		}
		if _, ok := failed[inode]; ok {
			continue
		}
		ns, err := x.open(pid, inode)
		if err != nil {
			// Without the privilege to enter it, retrying is pointless; a
			// PID that exited during the scan is retried on the next refresh.
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
				failed[inode] = struct{}{}
			}
			continue
		}
		next[inode] = ns
	}

	hostAddrs := map[netip.Addr]struct{}{}
	if addrs, err := host.addrs(); err == nil {
		for _, a := range addrs {
			hostAddrs[a] = struct{}{}
		}
	}
	byAddr := map[netip.Addr][]*netNS{}
	for _, ns := range next {
		addrs, err := ns.addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			byAddr[a] = append(byAddr[a], ns)
		}
	}

	// Close also holds refreshMu, so the index cannot be closed meanwhile.
	x.mu.Lock()
	x.namespaces, x.failed, x.byAddr, x.hostAddrs = next, failed, byAddr, hostAddrs
	x.mu.Unlock()
	// A namespace dropped here may still serve a lookup that read the old
	// index; its finder rejects requests after Close.
	for _, ns := range stale {
		_ = ns.close()
	}
	return nil
}

// scan returns one PID for each network namespace other than the host's.
func (x *netNSIndex) scan() (map[uint64]int, error) {
	dir, err := os.Open(x.proc)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	seen := map[uint64]int{}
	var link [64]byte
	for _, name := range names {
		pid, err := strconv.Atoi(name)
		if err != nil || pid <= 0 {
			continue
		}
		n, err := unix.Readlink(x.proc+"/"+name+"/ns/net", link[:])
		if err != nil {
			continue
		}
		inode, ok := parseNetNSLink(link[:n])
		if !ok || inode == x.self {
			continue
		}
		if _, ok := seen[inode]; !ok {
			seen[inode] = pid
		}
	}
	return seen, nil
}

// openPIDNetNS opens namespaces through proc, checking that the PID was
// not reused by a process of another namespace since the scan.
func openPIDNetNS(proc string) openNetNSFunc {
	return func(pid int, inode uint64) (*netNS, error) {
		f, err := os.Open(proc + "/" + strconv.Itoa(pid) + "/ns/net")
		if err != nil {
			return nil, err
		}
		defer f.Close()
		var stat unix.Stat_t
		if err := unix.Fstat(int(f.Fd()), &stat); err != nil {
			return nil, err
		}
		if stat.Ino != inode {
			return nil, errors.New("network namespace changed while opening")
		}
		return openNetNS(f, inode)
	}
}

func (x *netNSIndex) Close() error {
	x.refreshMu.Lock()
	defer x.refreshMu.Unlock()
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		return nil
	}
	x.closed = true
	namespaces, host := x.namespaces, x.host
	x.namespaces, x.byAddr, x.hostAddrs, x.host = map[uint64]*netNS{}, nil, nil, nil
	x.mu.Unlock()
	var err error
	for _, ns := range namespaces {
		err = errors.Join(err, ns.close())
	}
	if host != nil {
		err = errors.Join(err, host.close())
	}
	return err
}

var errNetNSIndexClosed = errors.New("network namespace index closed")

func netNSInode(path string) (uint64, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return 0, err
	}
	return stat.Ino, nil
}

func parseNetNSLink(link []byte) (uint64, bool) {
	s, ok := strings.CutPrefix(string(link), "net:[")
	if !ok {
		return 0, false
	}
	s, ok = strings.CutSuffix(s, "]")
	if !ok {
		return 0, false
	}
	inode, err := strconv.ParseUint(s, 10, 64)
	return inode, err == nil && inode != 0
}

// indexableAddr reports whether addr can identify one namespace. Loopback,
// link-local and unspecified addresses exist in every namespace.
func indexableAddr(addr netip.Addr) bool {
	return addr.IsValid() && !addr.IsUnspecified() && !addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() && !addr.IsMulticast()
}

// openNetNS creates a NETLINK_SOCK_DIAG and a NETLINK_ROUTE socket inside ns.
func openNetNS(ns *os.File, inode uint64) (*netNS, error) {
	diagFD, routeFD, err := socketsInNetNS(ns)
	if err != nil {
		return nil, err
	}
	if err := setNetlinkTimeouts(routeFD); err != nil {
		_ = unix.Close(diagFD)
		_ = unix.Close(routeFD)
		return nil, err
	}
	diag, err := NewSockDiagProcessDumper(os.NewFile(uintptr(diagFD), "sock_diag"), inode)
	if err != nil {
		_ = unix.Close(routeFD)
		return nil, err
	}
	route := &addrDumper{fd: routeFD, buf: make([]byte, 32<<10)}
	return &netNS{
		inode: inode,
		diag:  diag,
		addrs: route.dump,
		close: func() error { return errors.Join(diag.Close(), route.Close()) },
	}, nil
}

// openHostNetNS lists the addresses of the namespace yuhaiin runs in; its
// sockets are looked up by the regular host path.
func openHostNetNS() (*netNS, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err := setNetlinkTimeouts(fd); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	route := &addrDumper{fd: fd, buf: make([]byte, 32<<10)}
	return &netNS{addrs: route.dump, close: route.Close}, nil
}

// socketsInNetNS enters ns on a locked thread only long enough to create two
// sockets. A thread whose namespace cannot be restored is terminated.
func socketsInNetNS(ns *os.File) (diag, route int, err error) {
	type result struct {
		diag, route int
		err         error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		host, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			done <- result{-1, -1, err}
			return
		}
		defer host.Close()
		if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			done <- result{-1, -1, fmt.Errorf("enter network namespace: %w", err)}
			return
		}
		d, err1 := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_INET_DIAG)
		r, err2 := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
		if restoreErr := unix.Setns(int(host.Fd()), unix.CLONE_NEWNET); restoreErr != nil {
			closeFDs(d, r)
			done <- result{-1, -1, fmt.Errorf("restore network namespace: %w", restoreErr)}
			runtime.Goexit()
		}
		runtime.UnlockOSThread()
		if err := errors.Join(err1, err2); err != nil {
			closeFDs(d, r)
			done <- result{-1, -1, err}
			return
		}
		done <- result{d, r, nil}
	}()
	res := <-done
	return res.diag, res.route, res.err
}

func closeFDs(fds ...int) {
	for _, fd := range fds {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
}

// addrDumper lists the addresses of the namespace its socket belongs to.
type addrDumper struct {
	mu  sync.Mutex
	fd  int
	seq uint32
	buf []byte
}

func (a *addrDumper) dump() ([]netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fd < 0 {
		return nil, errNetNSIndexClosed
	}
	a.seq++
	req := make([]byte, unix.NLMSG_HDRLEN+unix.SizeofIfAddrmsg)
	binary.NativeEndian.PutUint32(req[0:4], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:6], unix.RTM_GETADDR)
	binary.NativeEndian.PutUint16(req[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:12], a.seq)
	if err := unix.Sendto(a.fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	for {
		n, _, err := unix.Recvfrom(a.fd, a.buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		msgs, err := syscall.ParseNetlinkMessage(a.buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != a.seq {
				continue
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return addrs, nil
			case unix.NLMSG_ERROR:
				if len(m.Data) >= 4 {
					if errno := int32(binary.NativeEndian.Uint32(m.Data[:4])); errno != 0 {
						return nil, unix.Errno(-errno)
					}
				}
				return addrs, nil
			case unix.RTM_NEWADDR:
				if addr, ok := parseIfAddr(m.Data); ok {
					addrs = append(addrs, addr)
				}
			}
		}
	}
}

func (a *addrDumper) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fd < 0 {
		return nil
	}
	err := unix.Close(a.fd)
	a.fd = -1
	return err
}

// parseIfAddr returns the local address of one RTM_NEWADDR message.
func parseIfAddr(b []byte) (netip.Addr, bool) {
	if len(b) < unix.SizeofIfAddrmsg {
		return netip.Addr{}, false
	}
	var local, address netip.Addr
	walkAttrs(b[unix.SizeofIfAddrmsg:], func(typ uint16, value []byte) {
		a, ok := netip.AddrFromSlice(value)
		if !ok {
			return
		}
		switch typ {
		case unix.IFA_LOCAL:
			local = a.Unmap()
		case unix.IFA_ADDRESS:
			address = a.Unmap()
		}
	})
	// IFA_LOCAL is the local end of a point-to-point IPv4 link, where
	// IFA_ADDRESS names the peer; IPv6 only carries IFA_ADDRESS.
	if local.IsValid() {
		address = local
	}
	return address, indexableAddr(address)
}

// NewProcessDumper returns a lookup that also covers container network
// namespaces, or the host-only lookup when the index cannot be created.
func NewProcessDumper() netapi.ProcessDumper {
	if d, err := NewContainerProcessDumper(); err == nil {
		return d
	}
	return HostProcessDumper{}
}
