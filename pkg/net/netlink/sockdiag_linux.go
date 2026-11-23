//go:build !android

package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"golang.org/x/sys/unix"
)

// SockDiagProcessDumper resolves socket owners inside one network
// namespace through a NETLINK_SOCK_DIAG socket that was created in that
// namespace and handed to this process, for example over SCM_RIGHTS by a
// session helper. sock_diag queries always see the namespace of the socket,
// so lookups never call setns and need no capability over the namespace.
// A failed lookup never consults the host namespace.
type SockDiagProcessDumper struct {
	// closeMu lets Close wait for in-flight lookups; mu serializes requests
	// on the single netlink socket.
	closeMu sync.RWMutex
	mu      sync.Mutex
	diag    *os.File
	netns   uint64
	seq     uint32
	buf     []byte
}

var _ netapi.ProcessDumper = (*SockDiagProcessDumper)(nil)

// NewSockDiagProcessDumper takes ownership of diag. netns is the nsfs
// inode of the namespace the socket was created in; owners are only
// accepted when their /proc/PID/ns/net matches it.
func NewSockDiagProcessDumper(diag *os.File, netns uint64) (*SockDiagProcessDumper, error) {
	if netns == 0 {
		_ = diag.Close()
		return nil, errors.New("sock_diag process dumper: invalid namespace inode")
	}
	fd := int(diag.Fd())
	domain, err1 := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	protocol, err2 := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
	if err := errors.Join(err1, err2); err != nil || domain != unix.AF_NETLINK || protocol != unix.NETLINK_INET_DIAG {
		_ = diag.Close()
		return nil, errors.Join(errors.New("sock_diag process dumper: descriptor is not a NETLINK_SOCK_DIAG socket"), err)
	}
	// Requests use blocking syscalls bounded by socket timeouts, as the
	// netlink package does; the descriptor never enters Go's poller.
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = diag.Close()
		return nil, err
	}
	timeout := unix.NsecToTimeval(netNSDiagTimeout.Nanoseconds())
	if err := errors.Join(unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout),
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &timeout)); err != nil {
		_ = diag.Close()
		return nil, err
	}
	return &SockDiagProcessDumper{diag: diag, netns: netns, buf: make([]byte, 32<<10)}, nil
}

// ProcessName implements [netapi.ProcessDumper] for sockets in the namespace.
func (d *SockDiagProcessDumper) ProcessName(network string, src, dst netapi.Address) (netapi.Process, error) {
	ip, to, err := ProcessAddrs(src, dst)
	if err != nil {
		return netapi.Process{}, err
	}
	return d.FindProcessName(network, ip, to)
}

// FindProcessName resolves the owner of the socket local -> remote.
func (d *SockDiagProcessDumper) FindProcessName(network string, local, remote netip.AddrPort) (netapi.Process, error) {
	d.closeMu.RLock()
	defer d.closeMu.RUnlock()
	if d.diag == nil {
		return netapi.Process{}, net.ErrClosed
	}
	if len(network) < 3 {
		return netapi.Process{}, fmt.Errorf("ErrInvalidNetwork: %s", network)
	}
	var protocol uint8
	switch network[:3] {
	case "tcp":
		protocol = unix.IPPROTO_TCP
	case "udp":
		protocol = unix.IPPROTO_UDP
	default:
		return netapi.Process{}, fmt.Errorf("ErrInvalidNetwork: %s", network)
	}
	socket, err := d.lookup(protocol, local, remote)
	if err != nil {
		return netapi.Process{}, err
	}
	name, pid, err := resolveProcessNameInNetNSAt("/proc", socket.inode, socket.uid, d.netns, defaultProcSearchCalls)
	if err != nil {
		return netapi.Process{}, err
	}
	return netapi.Process{Path: name, Uid: uint(socket.uid), Pid: pid}, nil
}

type diagSocket struct {
	local, remote netip.AddrPort
	uid, inode    uint32
}

// lookup queries IPv4 sockets and, for IPv4 addresses, also dual-stack
// IPv6 sockets that carry the address as an IPv4-mapped IPv6 address.
func (d *SockDiagProcessDumper) lookup(protocol uint8, local, remote netip.AddrPort) (diagSocket, error) {
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	families := []uint8{unix.AF_INET6}
	if local.Addr().Is4() {
		families = []uint8{unix.AF_INET, unix.AF_INET6}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var best diagSocket
	bestScore := 0
	for _, family := range families {
		sockets, err := d.dump(family, protocol, local.Port(), remote.Port())
		if err != nil {
			return diagSocket{}, err
		}
		for _, s := range sockets {
			if score := matchScore(protocol, s, local, remote); score > bestScore {
				best, bestScore = s, score
			}
		}
		if bestScore >= 3 {
			break
		}
	}
	if bestScore == 0 {
		return diagSocket{}, errors.New("socket not found")
	}
	return best, nil
}

// matchScore ranks a socket: an exact 4-tuple beats an unconnected socket
// bound to the local address, which beats a wildcard-bound socket.
func matchScore(protocol uint8, s diagSocket, local, remote netip.AddrPort) int {
	if s.local.Port() != local.Port() {
		return 0
	}
	localExact := s.local.Addr() == local.Addr()
	if !localExact && !s.local.Addr().IsUnspecified() {
		return 0
	}
	remoteExact := s.remote == remote
	if !remoteExact {
		if protocol == unix.IPPROTO_TCP || !s.remote.Addr().IsUnspecified() || s.remote.Port() != 0 {
			return 0
		}
	}
	switch {
	case localExact && remoteExact:
		return 3
	case localExact:
		return 2
	default:
		return 1
	}
}

const (
	sockDiagByFamily = 20
	inetDiagReqLen   = 56
	inetDiagMsgLen   = 72
	inetDiagNoCookie = ^uint32(0)
)

// dump returns the namespace's sockets with the given ports. The kernel
// filters TCP and UDP dumps by source and destination port.
func (d *SockDiagProcessDumper) dump(family, protocol uint8, sport, dport uint16) ([]diagSocket, error) {
	d.seq++
	req := make([]byte, unix.NLMSG_HDRLEN+inetDiagReqLen)
	binary.NativeEndian.PutUint32(req[0:4], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:6], sockDiagByFamily)
	binary.NativeEndian.PutUint16(req[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:12], d.seq)
	r := req[unix.NLMSG_HDRLEN:]
	r[0], r[1] = family, protocol
	binary.NativeEndian.PutUint32(r[4:8], ^uint32(0)) // all states
	binary.BigEndian.PutUint16(r[8:10], sport)
	if protocol == unix.IPPROTO_TCP {
		binary.BigEndian.PutUint16(r[10:12], dport)
	}
	binary.NativeEndian.PutUint32(r[48:52], inetDiagNoCookie)
	binary.NativeEndian.PutUint32(r[52:56], inetDiagNoCookie)
	fd := int(d.diag.Fd())
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("sock_diag request: %w", err)
	}
	var sockets []diagSocket
	for {
		n, _, err := unix.Recvfrom(fd, d.buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("sock_diag response: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(d.buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != d.seq {
				continue // a late reply to an earlier, timed-out request
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return sockets, nil
			case unix.NLMSG_ERROR:
				if len(m.Data) >= 4 {
					if errno := int32(binary.NativeEndian.Uint32(m.Data[:4])); errno != 0 {
						return nil, fmt.Errorf("sock_diag: %w", unix.Errno(-errno))
					}
				}
				return sockets, nil
			case sockDiagByFamily:
				if s, ok := parseInetDiag(m.Data); ok {
					sockets = append(sockets, s)
				}
			}
		}
	}
}

func parseInetDiag(b []byte) (diagSocket, bool) {
	if len(b) < inetDiagMsgLen {
		return diagSocket{}, false
	}
	family := b[0]
	sport, dport := binary.BigEndian.Uint16(b[4:6]), binary.BigEndian.Uint16(b[6:8])
	var src, dst netip.Addr
	switch family {
	case unix.AF_INET:
		src, dst = netip.AddrFrom4([4]byte(b[8:12])), netip.AddrFrom4([4]byte(b[24:28]))
	case unix.AF_INET6:
		src, dst = netip.AddrFrom16([16]byte(b[8:24])).Unmap(), netip.AddrFrom16([16]byte(b[24:40])).Unmap()
	default:
		return diagSocket{}, false
	}
	return diagSocket{
		local:  netip.AddrPortFrom(src, sport),
		remote: netip.AddrPortFrom(dst, dport),
		uid:    binary.NativeEndian.Uint32(b[64:68]),
		inode:  binary.NativeEndian.Uint32(b[68:72]),
	}, true
}

// Close releases the sock_diag socket after in-flight lookups complete.
func (d *SockDiagProcessDumper) Close() error {
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	if d.diag == nil {
		return nil
	}
	err := d.diag.Close()
	d.diag = nil
	return err
}
