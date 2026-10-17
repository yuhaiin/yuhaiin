//go:build darwin && !ios

package device

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	wun "github.com/tailscale/wireguard-go/tun"
)

// Explicit opt-in only. Creates an isolated point-to-point utun with a TEST-NET
// IPv4 peer and a ULA IPv6 host route. Never changes default routes or DNS.
// Total offered traffic is bounded and paced at <=1000 packets/s, with at most
// 128 packets in a TX call, after positively checking ENABLE_NETIF == 0.
func kernelUTUN(t testing.TB, mtu int) *wgDevice {
	t.Helper()
	if os.Getenv("YUHAIIN_RUN_UTUN_KERNEL") != "1" {
		t.Skip("opt-in real utun test: YUHAIIN_RUN_UTUN_KERNEL=1 (requires root)")
	}
	if os.Geteuid() != 0 {
		t.Skip("real utun test requires root; UDP fixtures are not a substitute")
	}
	if err := msgxAvailable(); err != nil {
		t.Fatal(err)
	}
	// Refuse an address collision rather than altering an existing interface.
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		ip, _, e := net.ParseCIDR(a.String())
		if e == nil && (ip.String() == "192.0.2.1" || ip.String() == "192.0.2.2" || ip.String() == "fd9c:3b2b:7a11::1" || ip.String() == "fd9c:3b2b:7a11::2") {
			t.Fatal("test address already in use", a)
		}
	}
	native, err := wun.CreateTUN("utun", mtu)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDevice(native, 4, mtu, false)
	t.Cleanup(func() { _ = d.Close() })
	name, err := native.Name()
	if err != nil {
		t.Fatal(err)
	}
	run := func(cmd string, args ...string) {
		t.Helper()
		out, e := exec.Command(cmd, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %s: %v", cmd, args, out, e)
		}
	}
	// Verify mode and byte-limited queue BEFORE any packet is injected.
	file := native.File()
	rc, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var setupErr error
	if err := rc.Control(func(fd uintptr) { _, _, setupErr = configureUTUNBatch(int(fd), mtu, 16) }); err != nil {
		t.Fatal(err)
	}
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	run("/sbin/ifconfig", name, "inet", "192.0.2.1", "192.0.2.2", "up")
	run("/sbin/ifconfig", name, "inet6", "fd9c:3b2b:7a11::1", "prefixlen", "128", "alias")
	run("/sbin/route", "-n", "add", "-inet6", "-host", "fd9c:3b2b:7a11::2", "-interface", name)
	t.Cleanup(func() {
		_ = exec.Command("/sbin/route", "-n", "delete", "-inet6", "-host", "fd9c:3b2b:7a11::2", "-interface", name).Run()
	})
	if err := file.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return d
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Reflect a valid, unfragmented UDP packet back to its host socket. No peer or
// external network is involved. IPv6 requires a real UDP pseudo-header checksum.
func reflectKernelUDP(b []byte) bool {
	if !completeUTUNFrame(b) {
		return false
	}
	p := b[4:]
	var udp []byte
	switch p[0] >> 4 {
	case 4:
		h := int(p[0]&15) * 4
		if p[9] != 17 || len(p) < h+8 || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
			return false
		}
		for i := range 4 {
			p[12+i], p[16+i] = p[16+i], p[12+i]
		}
		p[10], p[11] = 0, 0
		binary.BigEndian.PutUint16(p[10:12], ipChecksum(p[:h]))
		udp = p[h:]
	case 6:
		if p[6] != 17 || len(p) < 48 {
			return false
		}
		for i := range 16 {
			p[8+i], p[24+i] = p[24+i], p[8+i]
		}
		udp = p[40:]
	default:
		return false
	}
	udp[0], udp[2] = udp[2], udp[0]
	udp[1], udp[3] = udp[3], udp[1]
	udp[6], udp[7] = 0, 0
	if p[0]>>4 == 6 {
		pseudo := make([]byte, 40+len(udp))
		copy(pseudo, p[8:40])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(udp)))
		pseudo[39] = 17
		copy(pseudo[40:], udp)
		c := ipChecksum(pseudo)
		if c == 0 {
			c = 0xffff
		}
		binary.BigEndian.PutUint16(udp[6:8], c)
	}
	return true
}

// The matrix exercises both actual syscalls and the unchanged native path.
// This is a bounded functionality/latency experiment, NOT an end-to-end
// throughput benchmark. Pacing and setup deliberately dominate total duration.
func TestUTUNKernelExperiment(t *testing.T) {
	for _, mtu := range []int{1500, 9000} {
		t.Run(fmt.Sprint(mtu), func(t *testing.T) {
			native := kernelUTUN(t, mtu)
			rc, err := native.Device.File().SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			for _, pending := range []int{16, 32, 64, 128} {
				for _, batch := range []int{0, 1, 16, 32, 64, 128} {
					for _, family := range []int{4, 6} {
						for _, size := range []int{64, 512, 1400, mtu} {
							t.Run(fmt.Sprintf("queue%d/batch%d/IPv%d/%d", pending, batch, family, size), func(t *testing.T) {
								var rcv, actual int
								var se error
								if e := rc.Control(func(fd uintptr) { rcv, actual, se = configureUTUNBatch(int(fd), mtu, pending) }); e != nil {
									t.Fatal(e)
								}
								if se != nil {
									t.Fatal(se)
								}
								var dev netlink.Tun = native
								var batched *utunBatch
								if batch > 0 {
									batched = newUTUNBatch(native, rc, batch, socketSendBudget(t, rc))
									dev = batched
								}
								ip, peer, network := "192.0.2.1", "192.0.2.2", "udp4"
								overhead := 28
								if family == 6 {
									ip, peer, network = "fd9c:3b2b:7a11::1", "fd9c:3b2b:7a11::2", "udp6"
									overhead = 48
								}
								sock, e := net.DialUDP(network, &net.UDPAddr{IP: net.ParseIP(ip)}, &net.UDPAddr{IP: net.ParseIP(peer), Port: 40000})
								if e != nil {
									t.Fatal(e)
								}
								defer sock.Close()
								if e = sock.SetDeadline(time.Now().Add(5 * time.Second)); e != nil {
									t.Fatal(e)
								}
								if e = native.Device.File().SetDeadline(time.Now().Add(5 * time.Second)); e != nil {
									t.Fatal(e)
								}
								offered := min(128, actual) // stay within the byte-limited control queue
								payload := make([]byte, size-overhead)
								stamps := make([]time.Time, offered)
								for i := range offered {
									binary.BigEndian.PutUint32(payload, uint32(i))
									stamps[i] = time.Now()
									if _, e = sock.Write(payload); e != nil {
										t.Fatal(e)
									}
									time.Sleep(time.Millisecond) // bounded producer; never an unlimited TX flood
								}
								bufs := make([][]byte, dev.BatchSize())
								writeBufs := make([][]byte, len(bufs))
								sizes := make([]int, len(bufs))
								for i := range bufs {
									bufs[i] = make([]byte, mtu+4)
								}
								sent := 0
								for sent < offered {
									n, e := dev.Read(bufs, sizes)
									if e != nil {
										t.Fatal("utun read", e)
									}
									tx := writeBufs[:0]
									for i := range n {
										b := bufs[i][:sizes[i]+4]
										if reflectKernelUDP(b) {
											tx = append(tx, b)
										}
									}
									if len(tx) > 0 {
										n, e := dev.Write(tx)
										if e != nil || n != len(tx) {
											t.Fatal("utun write", n, e)
										}
										sent += n
									}
								}
								latencies := make([]int64, 0, offered)
								received := make([]bool, offered)
								for i := range offered {
									n, e := sock.Read(payload)
									if e != nil {
										t.Fatalf("kernel response %d/%d: %v", i, offered, e)
									}
									if n != size-overhead {
										t.Fatal("wrong UDP payload length", n)
									}
									seq := int(binary.BigEndian.Uint32(payload[:n]))
									if n != size-overhead || seq != i || seq >= offered || received[seq] {
										t.Fatal("lost, duplicate, corrupt or reordered kernel datagram", n, seq, i)
									}
									received[seq] = true
									latencies = append(latencies, time.Since(stamps[seq]).Nanoseconds())
								}
								slices.Sort(latencies)
								t.Logf("paced real utun: SO_RCVBUF=%d pending=%d mtu=%d offered=%d delivered=%d loss=0 RTT p50=%dns p95=%dns p99=%dns (includes intentional prequeue delay)", rcv, actual, mtu, offered, len(received), latencies[(offered-1)*50/100], latencies[(offered-1)*95/100], latencies[(offered-1)*99/100])
								if batched != nil {
									stats := batched.UTUNBatchStats()
									t.Logf("syscalls/stats: %+v", stats)
									if stats.Disabled || stats.TXUncertain != 0 {
										t.Fatal("kernel batching unexpectedly disabled")
									}
								}
							})
						}
					}
				}
			}
		})
	}
}
