// netlink
// copy from https://github.com/Dreamacro/clash/blob/master/component/process/process_linux.go
package netlink

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/mdlayher/netlink"
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

const (
	SOCK_DIAG_BY_FAMILY  = 20
	inetDiagRequestSize  = int(unsafe.Sizeof(inetDiagRequest{}))
	inetDiagResponseSize = int(unsafe.Sizeof(inetDiagResponse{}))
)

type inetDiagRequest struct {
	Family   byte
	Protocol byte
	Ext      byte
	Pad      byte
	States   uint32

	SrcPort [2]byte
	DstPort [2]byte
	Src     [16]byte
	Dst     [16]byte
	If      uint32
	Cookie  [2]uint32
}

type inetDiagResponse struct {
	Family  byte
	State   byte
	Timer   byte
	ReTrans byte

	SrcPort [2]byte
	DstPort [2]byte
	Src     [16]byte
	Dst     [16]byte
	If      uint32
	Cookie  [2]uint32

	Expires uint32
	RQueue  uint32
	WQueue  uint32
	UID     uint32
	INode   uint32
}

func FindProcessName(network string, ip net.IP, srcPort uint16) (string, error) {
	inode, uid, err := resolveSocketByNetlink(network, ip, srcPort)
	if err != nil {
		return "", err
	}

	return resolveProcessNameByProcSearch(inode, uid)
}

func resolveSocketByNetlink(network string, ip net.IP, srcPort uint16) (uint32, uint32, error) {
	request := &inetDiagRequest{
		States: 0xffffffff,
		Cookie: [2]uint32{0xffffffff, 0xffffffff},
	}

	if ip.To4() != nil {
		request.Family = unix.AF_INET
	} else {
		request.Family = unix.AF_INET6
	}

	if strings.HasPrefix(network, "tcp") {
		request.Protocol = unix.IPPROTO_TCP
	} else if strings.HasPrefix(network, "udp") {
		request.Protocol = unix.IPPROTO_UDP
	} else {
		return 0, 0, errors.New("err invalid network")
	}

	if v4 := ip.To4(); v4 != nil {
		copy(request.Src[:], v4)
	} else {
		copy(request.Src[:], ip)
	}

	binary.BigEndian.PutUint16(request.SrcPort[:], uint16(srcPort))

	conn, err := netlink.Dial(unix.NETLINK_SOCK_DIAG, nil)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()

	message := netlink.Message{
		Header: netlink.Header{
			Type:  SOCK_DIAG_BY_FAMILY,
			Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
		},
		Data: (*(*[inetDiagRequestSize]byte)(unsafe.Pointer(request)))[:],
	}

	messages, err := conn.Execute(message)
	if err != nil {
		return 0, 0, err
	}

	if len(messages) > 2 {
		return 0, 0, fmt.Errorf("multiple (%d) matching sockets", len(messages))
	}

	if len(messages) == 0 {
		return 0, 0, fmt.Errorf("message is empty")
	}

	if len(messages[0].Data) < inetDiagResponseSize {
		return 0, 0, fmt.Errorf("socket data short read (%d); want %d", len(messages[0].Data), inetDiagResponseSize)
	}

	response := (*inetDiagResponse)(unsafe.Pointer(&messages[0].Data[0]))
	return response.INode, response.UID, nil
}

func resolveProcessNameByProcSearch(inode, uid uint32) (string, error) {
	files, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	buffer := pool.GetBytes(unix.PathMax)
	defer pool.PutBytes(buffer)
	socket := fmt.Appendf(nil, "socket:[%d]", inode)

	for _, f := range files {
		if !f.IsDir() || !isPid(f.Name()) {
			continue
		}

		info, err := f.Info()
		if err != nil {
			return "", err
		}
		if info.Sys().(*syscall.Stat_t).Uid != uid {
			continue
		}

		processPath := filepath.Join("/proc", f.Name())
		fdPath := filepath.Join(processPath, "fd")

		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			n, err := unix.Readlink(filepath.Join(fdPath, fd.Name()), buffer)
			if err != nil {
				continue
			}

			if bytes.Equal(buffer[:n], socket) {
				return os.Readlink(filepath.Join(processPath, "exe"))
			}
		}
	}

	return "", fmt.Errorf("process of uid(%d),inode(%d) not found", uid, inode)
}

func isPid(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return !unicode.IsDigit(r)
	}) == -1
}
