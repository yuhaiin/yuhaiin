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
	read := func() ([]byte, error) { calls.Add(1); close(started); <-gate; return []byte{1}, nil }
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
	read = func() ([]byte, error) { calls.Add(1); return []byte{2}, nil }
	second := q.acquire(read)
	if second == first || calls.Load() != 2 {
		t.Fatal("completed snapshot retained across later queries")
	}
	want := errors.New("sysctl failed")
	s := q.acquire(func() ([]byte, error) { return nil, want })
	if !errors.Is(s.err, want) {
		t.Fatal(s.err)
	}
	s = q.acquire(read)
	if s.err != nil {
		t.Fatal("failed snapshot prevented retry")
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
					} else {
						if _, err := readTCPPCB(); err != nil {
							b.Error(err)
						}
					}
				}
			})
		})
	}
}
