// netlink
// copy from https://github.com/Dreamacro/clash/blob/master/component/process/process_linux.go
package netlink

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
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

func FindProcessName(network string, ip net.IP, srcPort uint16) (string, error) {
	isv6 := ip.To4() == nil
	var addr, remote net.Addr

	if strings.HasPrefix(network, "tcp") {
		addr = &net.TCPAddr{
			IP:   ip,
			Port: int(srcPort),
		}
		if isv6 {
			remote = &net.TCPAddr{
				IP:   net.IPv6zero,
				Port: 0,
			}
		} else {
			remote = &net.TCPAddr{
				IP:   net.IPv4zero,
				Port: 0,
			}
		}
	}

	if strings.HasPrefix(network, "udp") {
		addr = &net.UDPAddr{
			IP:   ip,
			Port: int(srcPort),
		}
		if isv6 {
			remote = &net.UDPAddr{
				IP:   net.IPv6zero,
				Port: 0,
			}
		} else {
			remote = &net.UDPAddr{
				IP:   net.IPv4zero,
				Port: 0,
			}
		}
	}

	st, err := netlink.SocketGet(addr, remote)
	if err != nil {
		return "", err
	}

	return resolveProcessNameByProcSearch(st.INode, st.UID)
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
