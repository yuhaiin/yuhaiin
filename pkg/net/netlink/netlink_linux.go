//go:build !android

package netlink

import (
	"bufio"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:embed tcplife.bt
var tcplife []byte

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

var (
	bpf             = NewBpfTcp()
	bpfSingleFlight = singleflight.Group[int, string]{}
)

func FindProcessName(network string, ip netip.AddrPort, to netip.AddrPort) (netapi.Process, error) {
	if bpf.active.Load() && network == "tcp" {
		pid, ok := bpf.findPid(ip, to)
		if !ok {
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

type pid struct {
	pid  int
	uid  int
	cmd  string
	time int64
}

type BpfTcp struct {
	active       atomic.Bool
	tcpconnect   *exec.Cmd
	timer        *time.Timer
	cache        syncmap.SyncMap[socket, pid]
	singleflight singleflight.Group[socket, struct{}]

	fieldsCache [][]byte
}

func (b *BpfTcp) findPid(srcaddr netip.AddrPort, dstaddr netip.AddrPort) (pid, bool) {
	// ! delete cache after find, because the statistic only call once
	return b.cache.LoadAndDelete(socket{srcaddr: srcaddr, dstaddr: dstaddr})
}

func NewBpfTcp() *BpfTcp {
	b := &BpfTcp{}

	if _, err := exec.LookPath("bpftrace"); err != nil {
		log.Warn("bpftrace not found", "err", err)
		return b
	}

	// TODO: maybe we also need tcp drop
	if err := b.startBpfTcp(); err != nil {
		log.Warn("start bpf tcp failed, fallback to tranditional method", "err", err)
		b.active.Store(false)
		return b
	}

	// remove expired cache(after 1min)
	b.timer = time.AfterFunc(time.Minute*10, func() {
		if !b.active.Load() {
			b.cache = syncmap.SyncMap[socket, pid]{}
			return
		}

		now := system.CheapNowNano()
		b.cache.Range(func(key socket, value pid) bool {
			if now-value.time > int64(time.Second*10) {
				b.cache.Delete(key)
			}

			return true
		})

		b.timer.Reset(time.Second * 30)
	})

	return b
}

func (b *BpfTcp) Close() error {
	var err error
	if b.tcpconnect != nil && b.tcpconnect.Process != nil {
		if er := b.tcpconnect.Process.Kill(); er != nil {
			err = errors.Join(err, er)
		}

		for b.active.Load() {
			runtime.Gosched()
		}
	}

	return err
}

func (b *BpfTcp) startBpfTcp() error {
	cmd := exec.Command("bpftrace", "-")

	cmd.Stdin = bytes.NewBuffer(tcplife)

	r, w := io.Pipe()

	cmd.Stdout = w
	cmd.Stderr = w

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		err := cmd.Wait()
		if err != nil {
			log.Warn("bpftrace", "err", err, "status", cmd.ProcessState)
		}

		w.CloseWithError(err)

		log.Warn("bpf tcp exited, fallback to tranditional method", "err", err)
		b.active.Store(false)
	}()

	go func() {
		scan := bufio.NewScanner(pool.GetBufioReader(r, 2048))

		if !scan.Scan() {
			return
		}

		b.active.Store(true)
		b.processLogs(scan.Bytes())

		for scan.Scan() {
			b.processLogs(scan.Bytes())
		}
	}()

	b.tcpconnect = cmd

	return nil
}

func (b *BpfTcp) processLogs(data []byte) {
	/*
		14:47:04 3893250  code             127.0.0.1                               59516  127.0.0.1                               37207
	*/

	sep := data

	fields := b.fieldsCache[:0]
	for range 7 {
		i := bytes.IndexByte(sep, ' ')
		if i < 0 {
			break
		}

		fields = append(fields, sep[:i])
		sep = sep[i+1:]
	}
	fields = append(fields, sep)

	if len(fields) < 7 {
		log.Info(unsafe.String(unsafe.SliceData(data), len(data)), "len", len(fields))
		return
	}

	cmd := fields[0]

	pidint, err := strconv.Atoi(unsafe.String(unsafe.SliceData(fields[1]), len(fields[1])))
	if err != nil {
		return
	}

	uid, err := strconv.Atoi(unsafe.String(unsafe.SliceData(fields[2]), len(fields[2])))
	if err != nil {
		return
	}

	sport, err := strconv.ParseUint(unsafe.String(unsafe.SliceData(fields[4]), len(fields[4])), 10, 16)
	if err != nil {
		return
	}

	saddr, err := netip.ParseAddr(unsafe.String(unsafe.SliceData(fields[3]), len(fields[3])))
	if err != nil {
		return
	}
	saddr = saddr.Unmap()

	dport, err := strconv.ParseUint(unsafe.String(unsafe.SliceData(fields[6]), len(fields[6])), 10, 16)
	if err != nil {
		return
	}

	daddr, err := netip.ParseAddr(unsafe.String(unsafe.SliceData(fields[5]), len(fields[5])))
	if err != nil {
		return
	}
	daddr = daddr.Unmap()

	switch unsafe.String(unsafe.SliceData(cmd), len(cmd)) {
	case "connect":
		key := socket{
			srcaddr: netip.AddrPortFrom(saddr, uint16(sport)),
			dstaddr: netip.AddrPortFrom(daddr, uint16(dport)),
		}

		_, _, _ = b.singleflight.Do(key, func() (struct{}, error) {
			_, _, _ = b.cache.LoadOrCreate(key, func() (pid, error) {
				return pid{
					pid:  pidint,
					uid:  uid,
					cmd:  string(bytes.Join(fields[7:], []byte(" "))),
					time: system.CheapNowNano(),
				}, nil
			})

			return struct{}{}, nil
		})
	case "close":
		src := netip.AddrPortFrom(saddr, uint16(sport))
		dst := netip.AddrPortFrom(daddr, uint16(dport))

		b.cache.Delete(socket{src, dst})
		b.cache.Delete(socket{dst, src})
	}
}
