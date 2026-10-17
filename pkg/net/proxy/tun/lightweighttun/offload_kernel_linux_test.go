//go:build linux && lightweight_kernel

package lightweighttun

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
)

type observedOffloadIO struct {
	lightweight.PacketIO
	reader                lightweight.PacketViewReader
	writer                lightweight.PacketBufferWriter
	largeReads, gsoWrites atomic.Uint64
	dropNext              atomic.Bool
	dropped               atomic.Uint64
	completeInput         []byte
}

func (p *observedOffloadIO) ReadPacketView() ([]byte, bool, error) {
	var b []byte
	var verified bool
	var err error
	if p.completeInput != nil {
		var n int
		n, err = p.PacketIO.ReadPacket(p.completeInput)
		b = p.completeInput[:n]
	} else {
		b, verified, err = p.reader.ReadPacketView()
	}
	if len(b) > 1500 {
		p.largeReads.Add(1)
	}
	return b, verified, err
}
func (p *observedOffloadIO) Headroom() int         { return p.writer.Headroom() }
func (p *observedOffloadIO) MaxGSOPacketSize() int { return p.writer.MaxGSOPacketSize() }
func (p *observedOffloadIO) WritePacketBuffer(b []byte, offset, size int) error {
	if size > 0 {
		p.gsoWrites.Add(1)
		if p.dropNext.Swap(false) {
			p.dropped.Add(1)
			return nil
		}
	}
	return p.writer.WritePacketBuffer(b, offset, size)
}

func kernelOffloadStack(t *testing.T, algorithm string, completeInput bool) (*lightweight.Stack, *observedOffloadIO) {
	t.Helper()
	d, err := device.OpenPacketWriter(netlink.TunScheme{Scheme: "tun", Name: "lwgso0"}, 1500)
	if err != nil {
		t.Fatal(err)
	}
	p, err := newPacketIO(d)
	if err != nil {
		_ = d.Close()
		t.Fatal(err)
	}
	if p.MaxGSOPacketSize() == 0 {
		_ = p.Close()
		t.Fatal("explicit offload suite requires Linux TCP TUN offload support")
	}
	observed := &observedOffloadIO{PacketIO: p, reader: p, writer: p}
	if completeInput {
		// Exercise the legacy complete-packet API too: it must finish partial
		// checksums before discarding the virtio metadata.
		observed.completeInput = make([]byte, 65575)
	}
	s, err := lightweight.New(lightweight.Config{
		Addresses:         []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")},
		CongestionControl: algorithm,
	}, observed)
	if err != nil {
		_ = p.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "set", "lwgso0", "mtu", "1500", "txqueuelen", "10000", "up"},
		{"addr", "add", "192.0.2.1/32", "dev", "lwgso0"},
		{"-6", "addr", "add", "2001:db8::1/128", "dev", "lwgso0", "nodad"},
		{"route", "add", "192.0.2.2/32", "dev", "lwgso0", "src", "192.0.2.1"},
		{"-6", "route", "add", "2001:db8::2/128", "dev", "lwgso0", "src", "2001:db8::1"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	return s, observed
}

func TestLinuxOffloadTCP(t *testing.T) {
	for _, algorithm := range []string{"reno", "cubic", "bbr"} {
		for _, v6 := range []bool{false, true} {
			for _, active := range []bool{false, true} {
				for _, loss := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/v6=%v/active=%v/loss=%v", algorithm, v6, active, loss), func(t *testing.T) {
						s, observed := kernelOffloadStack(t, algorithm, active && algorithm == "cubic")
						observed.dropNext.Store(loss)
						host, guest := "192.0.2.1:18080", "192.0.2.2:18080"
						if v6 {
							host, guest = "[2001:db8::1]:18080", "[2001:db8::2]:18080"
						}
						ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
						defer cancel()
						var l net.Listener
						var c net.Conn
						var err error
						if active {
							l, err = net.Listen("tcp", host)
						} else {
							l, err = s.ListenTCP(netip.MustParseAddrPort(guest))
						}
						if err != nil {
							t.Fatal(err)
						}
						defer l.Close()
						stop := context.AfterFunc(ctx, func() { _ = l.Close() })
						defer stop()
						if active {
							c, err = s.DialContextTCP(ctx, netip.MustParseAddrPort(host))
						} else {
							c, err = (&net.Dialer{}).DialContext(ctx, "tcp", guest)
						}
						if err != nil {
							t.Fatal(err)
						}
						defer c.Close()
						peer, err := l.Accept()
						if err != nil {
							t.Fatal(err)
						}
						defer peer.Close()
						deadline, _ := ctx.Deadline()
						_ = c.SetDeadline(deadline)
						_ = peer.SetDeadline(deadline)
						data := bytes.Repeat([]byte("independent-kernel-tcp-checksum"), 65536)
						done := make(chan error, 1)
						go func() {
							buf := make([]byte, len(data))
							_, err := io.ReadFull(peer, buf)
							if err == nil && !bytes.Equal(buf, data) {
								err = fmt.Errorf("peer payload mismatch")
							}
							if err == nil {
								_, err = peer.Write(buf)
							}
							if err == nil {
								err = peer.(interface{ CloseWrite() error }).CloseWrite()
							}
							done <- err
						}()
						if _, err := c.Write(data); err != nil {
							t.Fatal(err)
						}
						if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
							t.Fatal(err)
						}
						got, err := io.ReadAll(c)
						if err != nil || !bytes.Equal(got, data) {
							t.Fatalf("echo %d/%d: %v %+v", len(got), len(data), err, s.Stats())
						}
						if err := <-done; err != nil {
							t.Fatal(err)
						}
						if loss && (observed.dropped.Load() != 1 || s.Stats().Retransmissions == 0) {
							t.Fatalf("loss recovery bypassed: dropped=%d stats=%+v", observed.dropped.Load(), s.Stats())
						}
						if observed.largeReads.Load() == 0 || observed.gsoWrites.Load() == 0 {
							t.Fatalf("offloads were bypassed: large reads=%d GSO writes=%d", observed.largeReads.Load(), observed.gsoWrites.Load())
						}
					})
				}
			}
		}
	}
}

func TestLinuxOffloadUDPAndICMP(t *testing.T) {
	s, _ := kernelOffloadStack(t, "cubic", false)
	for _, v6 := range []bool{false, true} {
		dst, ping := "192.0.2.2:18081", "192.0.2.2"
		if v6 {
			dst, ping = "[2001:db8::2]:18081", "2001:db8::2"
		}
		server, err := s.ListenUDP(netip.MustParseAddrPort(dst))
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		client, err := net.Dial("udp", dst)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		_ = server.SetDeadline(time.Now().Add(5 * time.Second))
		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		data := bytes.Repeat([]byte("fragmented-offload-device"), 210)
		if _, err := client.Write(data); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 65535)
		n, addr, err := server.ReadFrom(buf)
		if err != nil || !bytes.Equal(buf[:n], data) {
			t.Fatalf("UDP receive %d: %v", n, err)
		}
		if _, err := server.WriteTo(buf[:n], addr); err != nil {
			t.Fatal(err)
		}
		n, err = client.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], data) {
			t.Fatalf("UDP reply %d: %v", n, err)
		}
		if out, err := exec.Command("ping", "-c", "1", "-W", "2", ping).CombinedOutput(); err != nil {
			t.Fatalf("ping %s: %v %s", ping, err, out)
		}
	}
}
