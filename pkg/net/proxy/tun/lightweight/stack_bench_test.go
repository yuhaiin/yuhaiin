package lightweight

import (
	"bytes"
	"context"
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"io"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
)

func BenchmarkUDP(b *testing.B) {
	for _, size := range []int{64, 512, 1200} {
		for _, flows := range []int{1, 100} {
			b.Run(fmt.Sprintf("payload=%d/flows=%d", size, flows), func(b *testing.B) {
				a, z := stackPair(b)
				server, err := z.ListenUDP(netip.MustParseAddrPort("192.0.2.2:8080"))
				if err != nil {
					b.Fatal(err)
				}
				defer server.Close()
				clients := make([]*UDPConn, flows)
				for i := range clients {
					clients[i], err = a.DialUDP(netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.2:8080"))
					if err != nil {
						b.Fatal(err)
					}
					defer clients[i].Close()
				}
				payload := bytes.Repeat([]byte{0xa5}, size)
				buf := make([]byte, size)
				_ = server.SetReadDeadline(time.Now().Add(time.Minute))
				b.SetBytes(int64(size))
				b.ReportAllocs()
				i := 0
				for b.Loop() {
					if _, err := clients[i%flows].Write(payload); err != nil {
						b.Fatal(err)
					}
					n, _, err := server.ReadFrom(buf)
					if err != nil || n != size || !bytes.Equal(buf, payload) {
						b.Fatalf("datagram %d %v", n, err)
					}
					i++
				}
				b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "packets/s")
			})
		}
	}
}

func BenchmarkImpairedTCP(b *testing.B) {
	for _, algorithm := range []string{"reno", "cubic", "bbr"} {
		for _, profile := range linkProfiles {
			b.Run(algorithm+"/"+profile.name, func(b *testing.B) {
				r, err := newReferenceIO(1500)
				if err != nil {
					b.Fatal(err)
				}
				link := simulate(r, profile)
				s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, CongestionControl: algorithm, Profile: RemoteTunnel}, link)
				if err != nil {
					b.Fatal(err)
				}
				defer s.Close()
				dst := netip.MustParseAddrPort("192.0.2.2:8080")
				a, proto := refAddress(dst)
				l, err := gonet.ListenTCP(r.stack, a, proto)
				if err != nil {
					b.Fatal(err)
				}
				defer l.Close()
				ctx, cancel := context.WithTimeout(b.Context(), 10*time.Second)
				client, err := s.DialContextTCP(ctx, dst)
				cancel()
				if err != nil {
					b.Fatal(err)
				}
				server, err := l.Accept()
				if err != nil {
					b.Fatal(err)
				}
				_ = client.SetDeadline(time.Now().Add(time.Minute))
				_ = server.SetDeadline(time.Now().Add(time.Minute))
				transferWorkload(b, []net.Conn{client}, []net.Conn{server}, 65536, "upload")
				b.ReportMetric(float64(s.Stats().Retransmissions), "retransmits")
				b.ReportMetric(float64(link.drops.Load()), "link-drops")
			})
		}
	}
}

func BenchmarkPacketParse(b *testing.B) {
	payload := make([]byte, 1208)
	binaryPutUDP(payload)
	packet, _ := makeIP(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 17, payload, 1)
	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	for b.Loop() {
		p, err := ParsePacket(packet)
		if err != nil {
			b.Fatal(err)
		}
		if err = p.ValidateTransport(); err != nil {
			b.Fatal(err)
		}
	}
}
func binaryPutUDP(b []byte) { b[0] = 1; b[2] = 1; b[4] = byte(len(b) >> 8); b[5] = byte(len(b)) }

// transferWorkload is shared by in-memory and kernel/TUN benchmarks. Each
// iteration completes one payload on every flow and verifies its full content.
// It measures bulk upload/download plus a one-byte completion/request marker.
func transferWorkload(b *testing.B, clients, servers []net.Conn, size int, direction string, measure ...func(bool)) {
	b.Helper()
	for i, c := range clients {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_ = servers[i].SetDeadline(time.Now().Add(5 * time.Second))
	}
	payload := bytes.Repeat([]byte{0xa5}, size)
	results := make(chan error, len(clients))
	start := make(chan struct{})
	finished := make(chan struct{})
	jobs := make([]chan struct{}, len(clients))
	var workers sync.WaitGroup
	for i, server := range servers {
		workers.Go(func() {
			defer server.Close()
			var buf []byte
			if direction == "upload" {
				buf = make([]byte, size)
			}
			marker := []byte{1}
			for {
				if direction == "upload" {
					if _, e := io.ReadFull(server, buf); e != nil {
						return
					}
					if !bytes.Equal(buf, payload) {
						return
					}
					if _, e := server.Write(marker); e != nil {
						return
					}
				} else {
					if _, e := io.ReadFull(server, marker); e != nil {
						return
					}
					if _, e := server.Write(payload); e != nil {
						return
					}
				}
			}
		})
		jobs[i] = make(chan struct{})
		client := clients[i]
		workers.Go(func() {
			var buf []byte
			if direction == "download" {
				buf = make([]byte, size)
			}
			marker := []byte{1}
			<-start
			for {
				select {
				case <-finished:
					return
				case <-jobs[i]:
				}
				var e error
				if direction == "upload" {
					_, e = client.Write(payload)
					if e == nil {
						_, e = io.ReadFull(client, marker)
					}
				} else {
					_, e = client.Write(marker)
					if e == nil {
						_, e = io.ReadFull(client, buf)
						if e == nil && !bytes.Equal(buf, payload) {
							e = ErrMalformed
						}
					}
				}
				results <- e
			}
		})
	}
	defer func() {
		close(finished)
		for i, c := range clients {
			_ = c.Close()
			_ = servers[i].Close()
		}
		workers.Wait()
	}()
	close(start)
	latencies := make([]int64, 0, 100000)
	b.SetBytes(int64(size * len(clients)))
	b.ReportAllocs()
	if len(measure) > 0 {
		measure[0](true)
	}
	for b.Loop() {
		now := time.Now()
		for _, job := range jobs {
			job <- struct{}{}
		}
		for range clients {
			if e := <-results; e != nil {
				b.Fatal(e)
			}
		}
		if len(latencies) < cap(latencies) {
			latencies = append(latencies, time.Since(now).Nanoseconds())
		}
	}
	if len(measure) > 0 {
		measure[0](false)
	}
	slices.Sort(latencies)
	if len(latencies) > 0 {
		b.ReportMetric(float64(latencies[(len(latencies)*95+99)/100-1])/1000, "p95-us")
		b.ReportMetric(float64(latencies[(len(latencies)*99+99)/100-1])/1000, "p99-us")
	}
	runtime.GC()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	b.ReportMetric(float64(mem.HeapAlloc), "heap-live-B")
	b.ReportMetric(float64(runtime.NumGoroutine()), "goroutines")
}

func BenchmarkTCP(b *testing.B) {
	for _, algorithm := range []string{"reno", "cubic", "bbr"} {
		for _, mtu := range []int{1280, 1500, 9000} {
			for _, flows := range []int{1, 8, 100} {
				for _, size := range []int{64, 65536} {
					for _, direction := range []string{"upload", "download"} {
						b.Run(fmt.Sprintf("%s/mtu=%d/flows=%d/payload=%d/%s", algorithm, mtu, flows, size, direction), func(b *testing.B) {
							x, y := memoryPair()
							a, err := New(Config{MTU: mtu, CongestionControl: algorithm, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}, x)
							if err != nil {
								b.Fatal(err)
							}
							defer a.Close()
							z, err := New(Config{MTU: mtu, CongestionControl: algorithm, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}, y)
							if err != nil {
								b.Fatal(err)
							}
							defer z.Close()
							l, err := z.ListenTCP(netip.MustParseAddrPort("192.0.2.2:8080"))
							if err != nil {
								b.Fatal(err)
							}
							defer l.Close()
							clients, servers := make([]net.Conn, flows), make([]net.Conn, flows)
							for i := range clients {
								ctx, cancel := context.WithTimeout(b.Context(), 10*time.Second)
								clients[i], err = a.DialContextTCP(ctx, netip.MustParseAddrPort("192.0.2.2:8080"))
								cancel()
								if err != nil {
									b.Fatal(err)
								}
								servers[i], err = l.Accept()
								if err != nil {
									b.Fatal(err)
								}
							}
							transferWorkload(b, clients, servers, size, direction)
							b.ReportMetric(float64(a.Stats().Retransmissions+z.Stats().Retransmissions), "retransmits")
							b.ReportMetric(float64(a.Stats().Drops+z.Stats().Drops), "drops")
						})
					}
				}
			}
		}
	}
}

func BenchmarkIdleThousand(b *testing.B) {
	for b.Loop() {
		a, z := stackPair(b)
		l, err := z.ListenTCP(netip.MustParseAddrPort("192.0.2.2:8080"))
		if err != nil {
			b.Fatal(err)
		}
		for range 1000 {
			c, err := a.DialContextTCP(b.Context(), netip.MustParseAddrPort("192.0.2.2:8080"))
			if err != nil {
				b.Fatal(err)
			}
			if _, err = l.Accept(); err != nil {
				b.Fatal(err)
			}
			_ = c
		}
		b.ReportMetric(float64(a.Stats().MemoryBytes+z.Stats().MemoryBytes)/2000, "accounted-B/conn")
		b.ReportMetric(float64(runtime.NumGoroutine()), "goroutines")
		_ = l.Close()
		_ = a.Close()
		_ = z.Close()
	}
}
