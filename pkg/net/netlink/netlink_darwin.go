package netlink

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"golang.org/x/sys/unix"
)

const (
	procpidpathinfo     = 0xb
	procpidpathinfosize = 1024
	proccallnumpidinfo  = 0x2
)

var structSize = func() int {
	value, _ := syscall.Sysctl("kern.osrelease")
	major, _, _ := strings.Cut(value, ".")
	n, _ := strconv.ParseInt(major, 10, 64)
	switch true {
	case n >= 22:
		return 408
	default:
		// from darwin-xnu/bsd/netinet/in_pcblist.c:get_pcblist_n
		// size/offset are round up (aligned) to 8 bytes in darwin
		// rup8(sizeof(xinpcb_n)) + rup8(sizeof(xsocket_n)) +
		// 2 * rup8(sizeof(xsockbuf_n)) + rup8(sizeof(xsockstat_n))
		return 384
	}
}()

func FindProcessName(network string, ip netip.AddrPort, dst netip.AddrPort) (netapi.Process, error) {
	var query *pcbQuery
	var read func() ([]byte, error)
	itemSize := structSize
	switch network {
	case "tcp":
		query, read = &tcpPCBQuery, readTCPPCB
		// rup8(sizeof(xtcpcb_n))
		itemSize += 208
	case "udp":
		query, read = &udpPCBQuery, readUDPPCB
	default:
		return netapi.Process{}, fmt.Errorf("ErrInvalidNetwork: %s", network)
	}

	snapshot := query.acquire(read)
	if snapshot.err != nil {
		return netapi.Process{}, snapshot.err
	}
	pid, err := findPCBPID(snapshot.data, itemSize, network, ip, dst)
	if err != nil {
		return netapi.Process{}, err
	}
	// Resolve the path live; never cache a PID-to-path association across
	// queries because PIDs can be recycled when a process exits.
	path, err := getExecPathFromPID(pid)
	return netapi.Process{Path: path, Pid: uint(pid)}, err
}

func getExecPathFromPID(pid uint32) (string, error) {
	var buf [procpidpathinfosize]byte
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		proccallnumpidinfo,
		uintptr(pid),
		procpidpathinfo,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		procpidpathinfosize)
	if errno != 0 {
		return "", errno
	}

	return unix.ByteSliceToString(buf[:]), nil
}
