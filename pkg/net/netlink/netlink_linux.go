//go:build !android

package netlink

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink/tcplife"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
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
		_ = fdDir.Close()
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

var (
	bpf             *BpfTcp
	bpfSingleFlight = singleflight.Group[int, string]{}
)

func StartBpf() {
	bpf = NewBpfTcp()
}

func FindProcessName(network string, ip netip.AddrPort, to netip.AddrPort) (netapi.Process, error) {
	if bpf != nil && bpf.Active() /*&& network == "tcp" */ {
		pid, ok := bpf.findPid(network, ip, to)
		if !ok {
			if network == "udp" {
				return findProcessName(network, ip, to)
			}
			return netapi.Process{}, fmt.Errorf("can't find process: %v %v", ip, to)
		}

		var err error
		var path string
		path, _, _ = bpfSingleFlight.Do(pid.pid, func() (string, error) {
			path, err = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid.pid))
			if path == "" {
				path = pid.cmd
			}

			return path, nil
		})

		return netapi.Process{Pid: uint(pid.pid), Uid: uint(pid.uid), Path: path}, err
	}

	return findProcessName(network, ip, to)
}

func BpfCloser() io.Closer { return bpf }

type socket struct {
	srcaddr netip.AddrPort
	dstaddr netip.AddrPort
}

type pidEntry struct {
	cmd  string
	pid  int
	uid  int
	time int64
}

type BpfTcp struct {
	ctx          context.Context
	cancel       context.CancelFunc
	timer        *time.Timer
	singleflight singleflight.Group[socket, struct{}]
	tcpCache     syncmap.SyncMap[socket, pidEntry]
	udpCache     syncmap.SyncMap[netip.AddrPort, pidEntry]
}

func (b *BpfTcp) findPid(network string, srcaddr netip.AddrPort, dstaddr netip.AddrPort) (pidEntry, bool) {
	// ! delete cache after find, because the statistic only call once
	switch network {
	case "tcp":
		return b.tcpCache.LoadAndDelete(socket{srcaddr: srcaddr, dstaddr: dstaddr})
	case "udp":
		return b.udpCache.LoadAndDelete(srcaddr)
	}
	// return b.cache.LoadAndDelete(socket{srcaddr: srcaddr, dstaddr: dstaddr})
	return pidEntry{}, false
}

func (b *BpfTcp) Active() bool {
	select {
	case <-b.ctx.Done():
		return false
	default:
		return true
	}
}

func NewBpfTcp() *BpfTcp {
	ctx, cancel := context.WithCancel(context.Background())

	b := &BpfTcp{
		ctx:    ctx,
		cancel: cancel,
	}

	go func() {
		defer b.cancel()
		if err := b.startBpfv2(ctx); err != nil {
			log.Warn("start bpf tcp failed, fallback to tranditional method", "err", err)
		}
	}()

	// remove expired cache(after 1min)
	b.timer = time.AfterFunc(time.Minute*10, func() {
		select {
		case <-b.ctx.Done():
			b.udpCache.Clear()
			b.tcpCache.Clear()
			return
		default:
		}

		now := system.CheapNowNano()
		b.tcpCache.Range(func(key socket, value pidEntry) bool {
			if now-value.time > int64(time.Second*10) {
				b.tcpCache.Delete(key)
			}
			return true
		})

		b.udpCache.Range(func(key netip.AddrPort, value pidEntry) bool {
			if now-value.time > int64(time.Second*10) {
				b.udpCache.Delete(key)
			}
			return true
		})

		b.timer.Reset(time.Second * 30)
	})

	return b
}

func (b *BpfTcp) Close() error {
	if b == nil {
		return nil
	}

	b.cancel()

	if b.timer != nil {
		b.timer.Stop()
	}

	return nil
}

func (b *BpfTcp) startBpfv2(ctx context.Context) error {
	return tcplife.MonitorEvents(ctx, func(e tcplife.Event) {
		var saddr, daddr netip.Addr
		switch e.Family {
		case unix.AF_INET:
			saddr = netip.AddrFrom4([4]byte(e.Saddr[:4])).Unmap()
			daddr = netip.AddrFrom4([4]byte(e.Daddr[:4])).Unmap()
		case unix.AF_INET6:
			saddr = netip.AddrFrom16(e.Saddr).Unmap()
			daddr = netip.AddrFrom16(e.Daddr).Unmap()
		}
		switch e.Action {
		case 1:
			var key socket
			var cache func(socket, func() (pidEntry, error)) (pidEntry, bool, error)

			switch e.Network {
			case tcplife.TCP:
				key = socket{
					srcaddr: netip.AddrPortFrom(saddr, e.Sport),
					dstaddr: netip.AddrPortFrom(daddr, e.Dport),
				}
				cache = b.tcpCache.LoadOrCreate

			case tcplife.UDP:
				key = socket{
					srcaddr: netip.AddrPortFrom(saddr, e.Sport),
				}
				cache = func(s socket, f func() (pidEntry, error)) (pidEntry, bool, error) {
					return b.udpCache.LoadOrCreate(s.srcaddr, f)
				}
			}

			if cache == nil {
				return
			}

			_, _, _ = b.singleflight.Do(key, func() (struct{}, error) {
				_, _, _ = cache(key, func() (pidEntry, error) {
					return pidEntry{
						pid:  int(e.Pid),
						uid:  int(e.Uid),
						cmd:  string(bytes.TrimRight(e.Comm[:], "\x00")),
						time: system.CheapNowNano(),
					}, nil
				})

				return struct{}{}, nil
			})

		case 2:
			src := netip.AddrPortFrom(saddr, e.Sport)
			dst := netip.AddrPortFrom(daddr, e.Dport)

			switch e.Network {
			case tcplife.TCP:
				b.tcpCache.Delete(socket{src, dst})
				b.tcpCache.Delete(socket{dst, src})
			case tcplife.UDP:
				b.udpCache.Delete(src)
				b.udpCache.Delete(dst)
			}
		}
	})
}
