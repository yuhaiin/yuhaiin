package netlink

import (
	"encoding/binary"
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

func FindProcessName(network string, ip netip.AddrPort, _ netip.AddrPort) (netapi.Process, error) {
	var spath string
	switch network {
	case "tcp":
		spath = "net.inet.tcp.pcblist_n"
	case "udp":
		spath = "net.inet.udp.pcblist_n"
	default:
		return netapi.Process{}, fmt.Errorf("ErrInvalidNetwork: %s", network)
	}

	value, err := syscall.Sysctl(spath)
	if err != nil {
		return netapi.Process{}, err
	}

	buf := []byte(value)
	itemSize := structSize
	if network == "tcp" {
		// rup8(sizeof(xtcpcb_n))
		itemSize += 208
	}

	// skip the first xinpgen(24 bytes) block
	for i := 24; i+itemSize <= len(buf); i += itemSize {
		// offset of xinpcb_n and xsocket_n
		inp, so := i, i+104

		srcPort := binary.BigEndian.Uint16(buf[inp+18 : inp+20])
		if ip.Port() != srcPort {
			continue
		}

		// xinpcb_n.inp_vflag
		flag := buf[inp+44]

		var (
			srcIP     netip.Addr
			srcIsIPv4 bool
		)

		isIPv4 := ip.Addr().Is4()

		switch {
		case flag&0x1 > 0 && isIPv4:
			// ipv4
			srcIP, _ = netip.AddrFromSlice(buf[inp+76 : inp+80])
			srcIsIPv4 = true
		case flag&0x2 > 0 && !isIPv4:
			// ipv6
			srcIP, _ = netip.AddrFromSlice(buf[inp+64 : inp+80])
		default:
			continue
		}

		if ip.Addr().Compare(srcIP) == 0 {
			// xsocket_n.so_last_pid
			pid := readNativeUint32(buf[so+68 : so+72])
			path, err := getExecPathFromPID(pid)
			return netapi.Process{
				Path: path,
				Pid:  uint(pid),
			}, err
		}

		// udp packet connection may be not equal with srcIP
		if network == "udp" && srcIP.IsUnspecified() && isIPv4 == srcIsIPv4 {
			fallbackUDPPid := readNativeUint32(buf[so+68 : so+72])
			fallbackUDPProcess, _ := getExecPathFromPID(fallbackUDPPid)

			if fallbackUDPProcess != "" {
				return netapi.Process{
					Path: fallbackUDPProcess,
					Pid:  uint(fallbackUDPPid),
				}, nil
			}
		}
	}
	return netapi.Process{}, fmt.Errorf("not found")
}

func getExecPathFromPID(pid uint32) (string, error) {
	buf := make([]byte, procpidpathinfosize)
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

	return unix.ByteSliceToString(buf), nil
}

func readNativeUint32(b []byte) uint32 {
	return *(*uint32)(unsafe.Pointer(&b[0]))
}
