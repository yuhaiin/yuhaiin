package netlink

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
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

func FindProcessName(network string, ip net.IP, srcPort uint16, to net.IP, toPort uint16) (netapi.Process, error) {
	var addr net.Addr
	var remote []net.Addr

	if len(network) < 3 {
		return netapi.Process{}, fmt.Errorf("ErrInvalidNetwork: %s", network)
	}

	network = network[0:3]

	switch network {
	case "tcp":
		addr = &net.TCPAddr{IP: ip, Port: int(srcPort)}
		remote = []net.Addr{&net.TCPAddr{IP: to, Port: int(toPort)}}
	case "udp":
		addr = &net.UDPAddr{IP: ip, Port: int(srcPort)}
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
		st, err = netlink.SocketGet(addr, r)
		if err == nil {
			break
		}
	}

	if st == nil {
		return netapi.Process{}, err
	}

	name, pid, err := resolveProcessNameByProcSearch(st.INode, st.UID)
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
	procDir, err := os.Open("/proc")
	if err != nil {
		return "", 0, err
	}
	defer procDir.Close()

	pids, err := procDir.Readdirnames(-1)
	if err != nil {
		return "", 0, err
	}

	expectedSocketName := fmt.Appendf(nil, "socket:[%d]", inode)

	pathBuffer := pool.NewBufferSize(1024)
	defer pathBuffer.Reset()

	readlinkBuffer := pool.GetBytes(32)
	defer pool.PutBytes(readlinkBuffer)

	_, _ = pathBuffer.WriteString("/proc/")

	for _, pidstr := range pids {
		pid, err := strconv.Atoi(pidstr)
		if err != nil {
			continue
		}

		pathBuffer.Truncate(len("/proc/"))
		_, _ = pathBuffer.WriteString(pidstr)

		stat := &unix.Stat_t{}
		err = unix.Stat(pathBuffer.String(), stat)
		if err != nil {
			continue
		}

		if stat.Uid != uid {
			continue
		}

		_, _ = pathBuffer.WriteString("/fd/")
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
			_, _ = pathBuffer.WriteString(fd)

			n, err := unix.Readlink(pathBuffer.String(), readlinkBuffer)
			if err != nil {
				continue
			}

			if bytes.Equal(readlinkBuffer[:n], expectedSocketName) {
				path, err := os.Readlink("/proc/" + pidstr + "/exe")
				return path, uint(pid), err
			}
		}
	}

	return "", 0, fmt.Errorf("inode %d of uid %d not found", inode, uid)
}
