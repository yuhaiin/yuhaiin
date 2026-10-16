//go:build linux && lightweight_kernel

package lightweight

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// changingMTUIO models a router on the stack-to-kernel path. Oversized data
// gets a real ICMP quotation; the independent Linux TCP receiver provides all
// ACK/SACK/window behavior. Accepted bytes successively shrink the path.
type changingMTUIO struct {
	base     PacketIO
	incoming chan []byte
	done     chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
	mu       sync.Mutex
	accepted int
	stage    int
	limits   [3]int
	reports  [3]int
}

func newChangingMTUIO(base PacketIO) *changingMTUIO {
	p := &changingMTUIO{base: base, incoming: make(chan []byte, 1024), done: make(chan struct{}), limits: [3]int{4000, 2000, 1280}}
	p.wg.Go(func() {
		defer p.stop()
		b := make([]byte, 65575)
		for {
			n, err := base.ReadPacket(b)
			if n > 0 {
				select {
				case p.incoming <- bytes.Clone(b[:n]):
				case <-p.done:
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
	return p
}
func (p *changingMTUIO) stop()        { p.once.Do(func() { close(p.done); _ = p.base.Close() }) }
func (p *changingMTUIO) Close() error { p.stop(); p.wg.Wait(); return nil }
func (p *changingMTUIO) ReadPacket(b []byte) (int, error) {
	select {
	case data := <-p.incoming:
		if len(data) > len(b) {
			return 0, io.ErrShortBuffer
		}
		return copy(b, data), nil
	case <-p.done:
		return 0, net.ErrClosed
	}
}
func (p *changingMTUIO) WritePacket(b []byte) error {
	packet, err := ParsePacket(b)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if packet.Protocol == 6 && len(packet.Payload) > int(packet.Payload[12]>>4)*4 {
		for p.stage < 2 && p.accepted >= (p.stage+1)*(64<<10) {
			p.stage++
		}
		if len(b) > p.limits[p.stage] {
			reply, err := pmtuTestReply(packet, p.limits[p.stage])
			if err != nil {
				return err
			}
			p.reports[p.stage]++
			select {
			case p.incoming <- reply:
				return nil
			case <-p.done:
				return net.ErrClosed
			}
		}
		if err := p.base.WritePacket(b); err != nil {
			return err
		}
		p.accepted += len(packet.Payload) - int(packet.Payload[12]>>4)*4
		return nil
	}
	return p.base.WritePacket(b)
}
func TestLinuxKernelContinuousPMTU(t *testing.T) {
	for _, kind := range []string{"reno", "cubic", "bbr"} {
		for _, ipv6 := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ipv6=%t", kind, ipv6), func(t *testing.T) {
				path := newChangingMTUIO(kernelLink(t, 9000))
				s, err := New(Config{MTU: 9000, CongestionControl: kind, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")}}, path)
				if err != nil {
					_ = path.Close()
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = s.Close() })
				dst := "192.0.2.2:18082"
				if ipv6 {
					dst = "[2001:db8::2]:18082"
				}
				listener, err := s.ListenTCP(netip.MustParseAddrPort(dst))
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				peer, err := (&net.Dialer{}).DialContext(ctx, "tcp", dst)
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				server, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(10 * time.Second))
				_ = peer.SetDeadline(time.Now().Add(10 * time.Second))
				payload := bytes.Repeat([]byte("independent kernel PMTU validation"), 32768)
				sent := make(chan error, 1)
				go func() {
					_, err := server.Write(payload)
					if err == nil {
						err = server.(interface{ CloseWrite() error }).CloseWrite()
					}
					sent <- err
				}()
				got, err := io.ReadAll(peer)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("PMTU transfer %d/%d: %v", len(got), len(payload), err)
				}
				if err := <-sent; err != nil {
					t.Fatal(err)
				}
				path.mu.Lock()
				reports := path.reports
				path.mu.Unlock()
				for i, n := range reports {
					if n == 0 {
						t.Fatalf("path stage %d was not exercised: %v", i, reports)
					}
				}
				c := server.(*TCPConn)
				c.mu.Lock()
				mss, lost := c.mss, c.lost
				c.mu.Unlock()
				limit := 1280 - 40
				if ipv6 {
					limit -= 20
				}
				if mss > limit {
					t.Fatalf("final MSS %d exceeds %d", mss, limit)
				}
				if lost != 0 {
					t.Fatalf("PMTU-triggered repair was classified as congestion loss: %d bytes", lost)
				}
			})
		}
	}
}
