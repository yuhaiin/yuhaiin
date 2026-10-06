package netlink

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type pcbRecord struct {
	local, remote netip.AddrPort
	pid           uint32
}

func pcbFixture(size int, records ...pcbRecord) []byte {
	b := make([]byte, 24+size*len(records)+24)
	for n, r := range records {
		i := 24 + n*size
		binary.BigEndian.PutUint16(b[i+18:i+20], r.local.Port())
		binary.BigEndian.PutUint16(b[i+16:i+18], r.remote.Port())
		if r.local.Addr().Is4() {
			b[i+44] = 1
			ip := r.local.Addr().As4()
			copy(b[i+76:i+80], ip[:])
			ip = r.remote.Addr().As4()
			copy(b[i+60:i+64], ip[:])
		} else {
			b[i+44] = 2
			ip := r.local.Addr().As16()
			copy(b[i+64:i+80], ip[:])
			ip = r.remote.Addr().As16()
			copy(b[i+48:i+64], ip[:])
		}
		binary.NativeEndian.PutUint32(b[i+172:i+176], r.pid)
	}
	return b
}

func TestPCBPIDMatching(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		local := netip.MustParseAddrPort("127.0.0.1:12345")
		remote := netip.MustParseAddrPort("127.0.0.1:443")
		zero := netip.MustParseAddrPort("0.0.0.0:0")
		if v6 {
			local = netip.MustParseAddrPort("[::1]:12345")
			remote = netip.MustParseAddrPort("[::1]:443")
			zero = netip.MustParseAddrPort("[::]:0")
		}
		for _, size := range []int{384, 408} {
			wrongPeer := netip.AddrPortFrom(remote.Addr(), 80)
			tcp := pcbFixture(size+208, pcbRecord{local, wrongPeer, 11}, pcbRecord{local, remote, 22})
			if pid, err := findPCBPID(tcp, size+208, "tcp", local, remote); err != nil || pid != 22 {
				t.Fatalf("TCP pid=%d err=%v", pid, err)
			}
			wildcard := netip.AddrPortFrom(zero.Addr(), local.Port())
			udp := pcbFixture(size, pcbRecord{wildcard, zero, 11}, pcbRecord{local, zero, 22})
			if pid, err := findPCBPID(udp, size, "udp", local, remote); err != nil || pid != 22 {
				t.Fatalf("UDP exact pid=%d err=%v", pid, err)
			}
			udp = pcbFixture(size, pcbRecord{wildcard, zero, 11})
			if pid, err := findPCBPID(udp, size, "udp", local, remote); err != nil || pid != 11 {
				t.Fatalf("UDP wildcard pid=%d err=%v", pid, err)
			}
			if _, err := findPCBPID(udp[:25], size, "udp", local, remote); err == nil {
				t.Fatal("truncated record matched")
			}
			if _, err := findPCBPID(udp, 10, "udp", local, remote); err == nil {
				t.Fatal("invalid size accepted")
			}
		}
	}
}

func TestPCBQueryDoesNotRetainResults(t *testing.T) {
	var q pcbQuery
	var calls atomic.Int32
	gate, started := make(chan struct{}), make(chan struct{})
	read := func([]byte) ([]byte, error) { calls.Add(1); close(started); <-gate; return []byte{1}, nil }
	results := make(chan *pcbSnapshot, 33)
	go func() { results <- q.acquire(read) }()
	<-started
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			results <- q.acquire(read)
		})
	}
	deadline := time.Now().Add(time.Second)
	for {
		q.mu.Lock()
		joined := q.current.readers
		q.mu.Unlock()
		if joined == 33 {
			break
		}
		if time.Now().After(deadline) {
			close(gate)
			t.Fatal("queries did not join in-flight read")
		}
		runtime.Gosched()
	}
	close(gate)
	wg.Wait()
	first := <-results
	for range 32 {
		if <-results != first {
			t.Error("overlapping queries did not share")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("reads=%d", calls.Load())
	}
	for range 32 {
		q.release(first)
	}
	read = func(buf []byte) ([]byte, error) {
		calls.Add(1)
		if cap(buf) != 0 {
			t.Fatal("reused a buffer still held by a scanner")
		}
		return []byte{2}, nil
	}
	second := q.acquire(read)
	if second == first || calls.Load() != 2 {
		t.Fatal("completed snapshot retained across later queries")
	}
	if first.data[0] != 1 {
		t.Fatal("later query overwrote an active scanner's table")
	}
	q.release(first)
	s := q.acquire(func(buf []byte) ([]byte, error) {
		if cap(buf) != 1 {
			t.Fatal("did not recycle buffer after its last scanner finished")
		}
		buf = buf[:1]
		buf[0] = 3
		return buf, nil
	})
	if second.data[0] != 2 {
		t.Fatal("recycled buffer corrupted a different active snapshot")
	}
	q.release(second)
	q.release(s)
	want := errors.New("sysctl failed")
	s = q.acquire(func(buf []byte) ([]byte, error) { return buf[:0], want })
	if !errors.Is(s.err, want) {
		t.Fatal(s.err)
	}
	q.release(s)
	s = q.acquire(func(buf []byte) ([]byte, error) { return buf[:0], nil })
	if s.err != nil {
		t.Fatal("failed snapshot prevented retry")
	}
	q.release(s)
}

func TestPCBQueryBoundsSpareBuffer(t *testing.T) {
	var q pcbQuery
	s := q.acquire(func([]byte) ([]byte, error) { return make([]byte, 1<<20+1), nil })
	q.release(s)
	if q.spare != nil || s.data != nil {
		t.Fatal("oversized table retained after scanners finished")
	}
}

func TestPCBTableRead(t *testing.T) {
	t.Run("reuse and truncate", func(t *testing.T) {
		buf := make([]byte, 64)
		out, err := readPCBTable(buf[:0], func(data []byte, n *uintptr) error {
			if data == nil {
				*n = 32
			} else {
				data[0] = 7
				*n = 8
			}
			return nil
		})
		if err != nil || len(out) != 8 || &out[0] != &buf[0] || out[0] != 7 {
			t.Fatalf("buffer not reused/truncated: len=%d err=%v", len(out), err)
		}
	})
	t.Run("table grows between calls", func(t *testing.T) {
		reads := 0
		out, err := readPCBTable(nil, func(data []byte, n *uintptr) error {
			if data == nil {
				*n = uintptr(16384 * (reads + 1))
				return nil
			}
			reads++
			if reads == 1 {
				return unix.ENOMEM
			}
			if len(data) < 32768 {
				t.Fatal("retry did not resize the table")
			}
			*n = 100
			return nil
		})
		if err != nil || reads != 2 || len(out) != 100 {
			t.Fatalf("reads=%d len=%d err=%v", reads, len(out), err)
		}
	})
	for _, want := range []error{unix.EPERM, unix.ENOMEM} {
		t.Run(want.Error(), func(t *testing.T) {
			reads := 0
			out, err := readPCBTable(nil, func(data []byte, n *uintptr) error {
				if data == nil {
					*n = 32
					return nil
				}
				reads++
				data[0] = 7 // Partial output must not reach the scanner.
				return want
			})
			if err != want || len(out) != 0 || reads > 3 {
				t.Fatalf("reads=%d len=%d err=%v", reads, len(out), err)
			}
		})
	}
}

func TestFindDarwinProcessForLiveSockets(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			addr := "127.0.0.1:0"
			if network == "tcp6" {
				addr = "[::1]:0"
			}
			l, err := net.Listen(network, addr)
			if err != nil {
				t.Skip(err)
			}
			defer l.Close()
			c, err := net.Dial(network, l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			peer, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			p, err := FindProcessName("tcp", c.LocalAddr().(*net.TCPAddr).AddrPort(), c.RemoteAddr().(*net.TCPAddr).AddrPort())
			if err != nil || p.Pid != uint(os.Getpid()) || p.Path == "" {
				t.Fatalf("process=%+v err=%v", p, err)
			}
		})
	}
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	src := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(u.LocalAddr().(*net.UDPAddr).Port))
	p, err := FindProcessName("udp", src, netip.MustParseAddrPort("127.0.0.1:53"))
	if err != nil || p.Pid != uint(os.Getpid()) {
		t.Fatalf("UDP process=%+v err=%v", p, err)
	}
}

func BenchmarkPCBQuery(b *testing.B) {
	for _, shared := range []bool{false, true} {
		name := "Independent"
		if shared {
			name = "Overlapping"
		}
		b.Run(name, func(b *testing.B) {
			var q pcbQuery
			b.SetParallelism(4)
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if shared {
						s := q.acquire(readTCPPCB)
						if s.err != nil {
							b.Error(s.err)
						}
						q.release(s)
					} else {
						if _, err := readTCPPCB(nil); err != nil {
							b.Error(err)
						}
					}
				}
			})
		})
	}
}

func liveTCPProcessSocket(t testing.TB) (netip.AddrPort, netip.AddrPort) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	c, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	peer, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	return c.LocalAddr().(*net.TCPAddr).AddrPort(), c.RemoteAddr().(*net.TCPAddr).AddrPort()
}

func TestDarwinProcessQueryAllocationBudget(t *testing.T) {
	src, dst := liveTCPProcessSocket(t)
	lookup := func() {
		p, err := FindProcessName("tcp", src, dst)
		if err != nil || p.Pid != uint(os.Getpid()) || p.Path == "" {
			t.Fatalf("process=%+v err=%v", p, err)
		}
	}
	lookup() // Warm up the reusable table buffer.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 100 {
		lookup()
	}
	runtime.ReadMemStats(&after)
	if bytes := (after.TotalAlloc - before.TotalAlloc) / 100; bytes > 4096 {
		t.Fatalf("process lookup allocated %d bytes/query; want <= 4096 without copying the whole PCB table", bytes)
	}
}

func BenchmarkDarwinProcessQuery(b *testing.B) {
	src, dst := liveTCPProcessSocket(b)
	for _, reused := range []bool{false, true} {
		name := "SysctlRaw"
		if reused {
			name = "ReusedBuffer"
		}
		b.Run(name, func(b *testing.B) {
			var q pcbQuery
			read := func([]byte) ([]byte, error) { return unix.SysctlRaw("net.inet.tcp.pcblist_n") }
			if reused {
				read = readTCPPCB
			}
			b.ReportAllocs()
			for b.Loop() {
				s := q.acquire(read)
				if s.err != nil {
					b.Fatal(s.err)
				}
				pid, err := findPCBPID(s.data, structSize+208, "tcp", src, dst)
				q.release(s)
				if err != nil || pid != uint32(os.Getpid()) {
					b.Fatalf("pid=%d err=%v", pid, err)
				}
				path, err := getExecPathFromPID(pid)
				if err != nil || path == "" {
					b.Fatalf("path=%q err=%v", path, err)
				}
			}
		})
	}
}

func TestDarwinProcessQueriesParallel(t *testing.T) {
	src, dst := liveTCPProcessSocket(t)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 32 {
				p, err := FindProcessName("tcp", src, dst)
				if err != nil || p.Pid != uint(os.Getpid()) || p.Path == "" {
					t.Errorf("process=%+v err=%v", p, err)
					return
				}
			}
		})
	}
	wg.Wait()
}
