package netlink

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"

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

func FindProcessName(network string, ip net.IP, srcPort uint16, to net.IP, toPort uint16) (string, error) {
	var addr, remote net.Addr

	if strings.HasPrefix(network, "tcp") {
		addr = &net.TCPAddr{IP: ip, Port: int(srcPort)}
		remote = &net.TCPAddr{IP: to, Port: int(toPort)}
	}

	if strings.HasPrefix(network, "udp") {
		addr = &net.UDPAddr{IP: ip, Port: int(srcPort)}
		remote = &net.UDPAddr{IP: to, Port: int(toPort)}
	}

	st, err := netlink.SocketGet(addr, remote)
	if err != nil {
		return "", err
	}

	return resolveProcessNameByProcSearch(st.INode, st.UID)
}

func resolveProcessNameByProcSearch(inode, uid uint32) (string, error) {
	procDir, err := os.Open("/proc")
	if err != nil {
		return "", err
	}
	defer procDir.Close()

	pids, err := procDir.Readdirnames(-1)
	if err != nil {
		return "", err
	}

	expectedSocketName := fmt.Appendf(nil, "socket:[%d]", inode)

	pathBuffer := pool.GetBuffer()
	defer pool.PutBuffer(pathBuffer)

	readlinkBuffer := pool.GetBytesV2(32)
	defer pool.PutBytesV2(readlinkBuffer)

	pathBuffer.WriteString("/proc/")

	for _, pid := range pids {
		if !isPid(pid) {
			continue
		}

		pathBuffer.Truncate(len("/proc/"))
		pathBuffer.WriteString(pid)

		stat := &unix.Stat_t{}
		err = unix.Stat(pathBuffer.String(), stat)
		if err != nil {
			continue
		}

		if stat.Uid != uid {
			continue
		}

		pathBuffer.WriteString("/fd/")
		fdsPrefixLength := pathBuffer.Len()

		fdDir, err := os.Open(pathBuffer.String())
		if err != nil {
			continue
		}

		fds, err := fdDir.Readdirnames(-1)
		fdDir.Close()
		if err != nil {
			continue
		}

		for _, fd := range fds {
			pathBuffer.Truncate(fdsPrefixLength)
			pathBuffer.WriteString(fd)

			n, err := unix.Readlink(pathBuffer.String(), readlinkBuffer.Bytes())
			if err != nil {
				continue
			}

			if bytes.Equal(readlinkBuffer.Bytes()[:n], expectedSocketName) {
				return os.Readlink("/proc/" + pid + "/exe")
			}
		}
	}

	return "", fmt.Errorf("inode %d of uid %d not found", inode, uid)
}

func isPid(name string) bool {
	for _, c := range name {
		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}
