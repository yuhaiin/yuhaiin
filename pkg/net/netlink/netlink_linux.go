//go:build !android

package netlink

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

/*
https://stackoverflow.com/questions/10996242/how-to-get-the-pid-of-a-process-that-is-listening-on-a-certain-port-programmatic

Like netstat, you should read /proc/net/tcp.

Interpreting it:

	The second field, titled local_address, is the IP and port. 00000000:0050 would be HTTP (the port number is in hex).
	The 4th field, titled st, is the state. A is TCP_LISTEN.
	The 10th field, titled inode is the inode number (decimal this time).
	For each process, /proc/pid/fd/ contains an entry for each open file descriptor. ls -l for socket descriptors shows that it's a link to socket:[nnnnnn]. The number nnnnnn should match the inode number from /proc/net/tcp.

This makes finding the process quite tiresome, but possible.
Finding the right line in /proc/net/tcp isn't difficult, and then you can get the inode number.
Finding the process requires you to scan all processes, looking for one which refers this inode number. I know no better way.
*/

func findProcessName(network string, ip netip.AddrPort, to netip.AddrPort) (netapi.Process, error) {
	return findProcessNameWith(netlink.SocketGet, 0, network, ip, to)
}

// findProcessNameWith resolves one socket through socketGet. A nonzero netns
// restricts the owning process to that network namespace.
func findProcessNameWith(socketGet func(local, remote net.Addr) (*netlink.Socket, error), netns uint64,
	network string, ip netip.AddrPort, to netip.AddrPort,
) (netapi.Process, error) {
	var addr net.Addr
	var remote []net.Addr

	if len(network) < 3 {
		return netapi.Process{}, fmt.Errorf("ErrInvalidNetwork: %s", network)
	}

	network = network[0:3]

	switch network {
	case "tcp":
		addr = net.TCPAddrFromAddrPort(ip)
		remote = []net.Addr{net.TCPAddrFromAddrPort(to)}
	case "udp":
		addr = net.UDPAddrFromAddrPort(ip)
		remote = []net.Addr{
			// &net.UDPAddr{IP: to, Port: int(toPort)},
			&net.UDPAddr{IP: net.IPv6zero, Port: 0},
			&net.UDPAddr{IP: net.IPv4zero, Port: 0},
		}
	default:
		return netapi.Process{}, fmt.Errorf("ErrInvalidNetwork: %s", network)
	}

	var st *netlink.Socket
	var err error

	for _, r := range remote {
		st, err = socketGet(addr, r)
		if err == nil {
			break
		}
	}

	if st == nil {
		return netapi.Process{}, err
	}

	name, pid, err := resolveProcessNameInNetNSAt("/proc", st.INode, st.UID, netns, defaultProcSearchCalls)
	if err != nil {
		return netapi.Process{}, err
	}

	return netapi.Process{
		Path: name,
		Uid:  uint(st.UID),
		Pid:  pid,
	}, nil
}

func resolveProcessNameByProcSearch(inode, uid uint32) (string, uint, error) {
	return resolveProcessNameByProcSearchAt("/proc", inode, uid, defaultProcSearchCalls)
}

// FindProcessName queries socket ownership on demand. No kernel tracing or
// background cache is required for this Linux fallback.
func FindProcessName(network string, ip netip.AddrPort, to netip.AddrPort) (netapi.Process, error) {
	return findProcessName(network, ip, to)
}

// NetNSProcessDumper resolves socket owners inside one network namespace
// only. It holds a single sock_diag socket created in that namespace, so
// lookups never call setns. A failed lookup never consults the host namespace.
type NetNSProcessDumper struct {
	mu     sync.RWMutex
	handle *netlink.Handle
	netns  uint64
}

var _ netapi.ProcessDumper = (*NetNSProcessDumper)(nil)

// NewNetNSProcessDumper binds a dumper to the network namespace file ns,
// such as /proc/PID/ns/net. The caller keeps ownership of ns. CAP_SYS_ADMIN
// is required to enter the namespace once while creating the socket.
func NewNetNSProcessDumper(ns *os.File) (*NetNSProcessDumper, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(ns.Fd()), &stat); err != nil {
		return nil, err
	}
	if stat.Ino == 0 {
		return nil, errors.New("netns process dumper: invalid namespace inode")
	}
	type result struct {
		handle *netlink.Handle
		err    error
	}
	done := make(chan result, 1)
	go func() {
		// The thread is never returned to the scheduler while it might still be
		// in the target namespace: on a failed restore the goroutine exits
		// locked, which terminates the OS thread.
		runtime.LockOSThread()
		host, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			done <- result{err: err}
			return
		}
		defer host.Close()
		if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			done <- result{err: fmt.Errorf("netns process dumper: enter namespace: %w", err)}
			return
		}
		// No namespace handle is passed, so vishvananda/netlink creates the
		// socket in this thread's current (target) namespace without setns.
		handle, err := netlink.NewHandle(unix.NETLINK_INET_DIAG)
		if restoreErr := unix.Setns(int(host.Fd()), unix.CLONE_NEWNET); restoreErr != nil {
			if handle != nil {
				handle.Close()
			}
			done <- result{err: fmt.Errorf("netns process dumper: restore namespace: %w", restoreErr)}
			runtime.Goexit()
		}
		runtime.UnlockOSThread()
		done <- result{handle, err}
	}()
	r := <-done
	if r.err != nil {
		return nil, r.err
	}
	if err := r.handle.SetSocketTimeout(netNSDiagTimeout); err != nil {
		r.handle.Close()
		return nil, err
	}
	return &NetNSProcessDumper{handle: r.handle, netns: stat.Ino}, nil
}

const netNSDiagTimeout = 2 * time.Second

// ProcessName implements [netapi.ProcessDumper] for sockets in the namespace.
func (d *NetNSProcessDumper) ProcessName(network string, src, dst netapi.Address) (netapi.Process, error) {
	ip, to, err := ProcessAddrs(src, dst)
	if err != nil {
		return netapi.Process{}, err
	}
	return d.FindProcessName(network, ip, to)
}

// FindProcessName is the namespace-scoped equivalent of [FindProcessName].
func (d *NetNSProcessDumper) FindProcessName(network string, ip, to netip.AddrPort) (netapi.Process, error) {
	// Close must not race the request: a Handle without sockets silently
	// falls back to a new socket in the caller's (host) namespace.
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.handle == nil {
		return netapi.Process{}, net.ErrClosed
	}
	return findProcessNameWith(d.handle.SocketGet, d.netns, network, ip, to)
}

// Close releases the sock_diag socket after in-flight lookups complete.
func (d *NetNSProcessDumper) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handle != nil {
		d.handle.Close()
		d.handle = nil
	}
	return nil
}
