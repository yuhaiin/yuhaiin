package netlink

import (
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"golang.org/x/sys/windows"
)

var (
	modIphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")
)

func FindProcessName(network string, ip netip.AddrPort, to netip.AddrPort) (netapi.Process, error) {
	family := uint32(windows.AF_INET)
	if ip.Addr().Is6() {
		family = windows.AF_INET6
	}

	var protocol uint32
	switch network {
	case "tcp":
		protocol = windows.IPPROTO_TCP
	case "udp":
		protocol = windows.IPPROTO_UDP
	default:
		return netapi.Process{}, errors.New("ErrInvalidNetwork")
	}

	pid, err := findPidByConnectionEndpoint(family, protocol, ip, to)
	if err != nil {
		return netapi.Process{}, err
	}

	path, err := getExecPathFromPID(pid)
	if err != nil {
		return netapi.Process{}, err
	}

	return netapi.Process{
		Path: path,
		Pid:  uint(pid),
	}, nil
}

func findPidByConnectionEndpoint(family uint32, protocol uint32, from netip.AddrPort, to netip.AddrPort) (uint32, error) {
	buf := pool.GetBytes(0)
	defer pool.PutBytes(buf)

	bufSize := uint32(len(buf))

loop:
	for {
		var ret uintptr

		switch protocol {
		case windows.IPPROTO_TCP:
			ret, _, _ = procGetExtendedTcpTable.Call(
				uintptr(unsafe.Pointer(unsafe.SliceData(buf))),
				uintptr(unsafe.Pointer(&bufSize)),
				0,
				uintptr(family),
				4, // TCP_TABLE_OWNER_PID_CONNECTIONS
				0,
			)
		case windows.IPPROTO_UDP:
			ret, _, _ = procGetExtendedUdpTable.Call(
				uintptr(unsafe.Pointer(unsafe.SliceData(buf))),
				uintptr(unsafe.Pointer(&bufSize)),
				0,
				uintptr(family),
				1, // UDP_TABLE_OWNER_PID
				0,
			)
		default:
			return 0, errors.New("unsupported network")
		}

		switch ret {
		case 0:
			buf = buf[:bufSize]

			break loop
		case uintptr(windows.ERROR_INSUFFICIENT_BUFFER):
			pool.PutBytes(buf)
			buf = pool.GetBytes(int(bufSize))

			continue loop
		default:
			return 0, fmt.Errorf("syscall error: %d", ret)
		}
	}

	if len(buf) < int(unsafe.Sizeof(uint32(0))) {
		return 0, fmt.Errorf("invalid table size: %d", len(buf))
	}

	entriesSize := *(*uint32)(unsafe.Pointer(&buf[0]))

	switch protocol {
	case windows.IPPROTO_TCP:
		if family == windows.AF_INET {
			type MibTcpRowOwnerPid struct {
				State      uint32
				LocalAddr  [4]byte
				LocalPort  uint32
				RemoteAddr [4]byte
				RemotePort uint32
				OwningPid  uint32
			}

			if uint32(len(buf))-4 < entriesSize*uint32(unsafe.Sizeof(MibTcpRowOwnerPid{})) {
				return 0, fmt.Errorf("invalid tables size: %d", len(buf))
			}

			entries := unsafe.Slice((*MibTcpRowOwnerPid)(unsafe.Pointer(&buf[4])), entriesSize)
			for _, entry := range entries {
				localAddr := netip.AddrFrom4(entry.LocalAddr)
				localPort := windows.Ntohs(uint16(entry.LocalPort))
				remoteAddr := netip.AddrFrom4(entry.RemoteAddr)
				remotePort := windows.Ntohs(uint16(entry.RemotePort))

				if localAddr == from.Addr() && remoteAddr == to.Addr() && localPort == from.Port() && remotePort == to.Port() {
					return entry.OwningPid, nil
				}
			}
		} else {
			type MibTcp6RowOwnerPid struct {
				LocalAddr     [16]byte
				LocalScopeID  uint32
				LocalPort     uint32
				RemoteAddr    [16]byte
				RemoteScopeID uint32
				RemotePort    uint32
				State         uint32
				OwningPid     uint32
			}

			if uint32(len(buf))-4 < entriesSize*uint32(unsafe.Sizeof(MibTcp6RowOwnerPid{})) {
				return 0, fmt.Errorf("invalid tables size: %d", len(buf))
			}

			entries := unsafe.Slice((*MibTcp6RowOwnerPid)(unsafe.Pointer(&buf[4])), entriesSize)
			for _, entry := range entries {
				localAddr := netip.AddrFrom16(entry.LocalAddr)
				localPort := windows.Ntohs(uint16(entry.LocalPort))
				remoteAddr := netip.AddrFrom16(entry.RemoteAddr)
				remotePort := windows.Ntohs(uint16(entry.RemotePort))

				if localAddr == from.Addr() && remoteAddr == to.Addr() && localPort == from.Port() && remotePort == to.Port() {
					return entry.OwningPid, nil
				}
			}
		}
	case windows.IPPROTO_UDP:
		if family == windows.AF_INET {
			type MibUdpRowOwnerPid struct {
				LocalAddr [4]byte
				LocalPort uint32
				OwningPid uint32
			}

			if uint32(len(buf))-4 < entriesSize*uint32(unsafe.Sizeof(MibUdpRowOwnerPid{})) {
				return 0, fmt.Errorf("invalid tables size: %d", len(buf))
			}

			entries := unsafe.Slice((*MibUdpRowOwnerPid)(unsafe.Pointer(&buf[4])), entriesSize)
			for _, entry := range entries {
				localAddr := netip.AddrFrom4(entry.LocalAddr)
				localPort := windows.Ntohs(uint16(entry.LocalPort))

				if (localAddr == from.Addr() || localAddr.IsUnspecified()) && localPort == from.Port() {
					return entry.OwningPid, nil
				}
			}
		} else {
			type MibUdp6RowOwnerPid struct {
				LocalAddr    [16]byte
				LocalScopeId uint32
				LocalPort    uint32
				OwningPid    uint32
			}

			if uint32(len(buf))-4 < entriesSize*uint32(unsafe.Sizeof(MibUdp6RowOwnerPid{})) {
				return 0, fmt.Errorf("invalid tables size: %d", len(buf))
			}

			entries := unsafe.Slice((*MibUdp6RowOwnerPid)(unsafe.Pointer(&buf[4])), entriesSize)
			for _, entry := range entries {
				localAddr := netip.AddrFrom16(entry.LocalAddr)
				localPort := windows.Ntohs(uint16(entry.LocalPort))

				if (localAddr == from.Addr() || localAddr.IsUnspecified()) && localPort == from.Port() {
					return entry.OwningPid, nil
				}
			}
		}
	default:
		return 0, errors.New("ErrInvalidNetwork")
	}

	return 0, errors.New("ErrNotFound")
}

func getExecPathFromPID(pid uint32) (string, error) {
	// kernel process starts with a colon in order to distinguish with normal processes
	switch pid {
	case 0:
		// reserved pid for system idle process
		return ":System Idle Process", nil
	case 4:
		// reserved pid for windows kernel image
		return ":System", nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))

	err = windows.QueryFullProcessImageName(h, 0, &buf[0], &size)
	if err != nil {
		return "", err
	}

	return windows.UTF16ToString(buf[:size]), nil
}
