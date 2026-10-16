package direct

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const pingTimeout = 3 * time.Second

// Ping sends one ICMP Echo Request over a kernel ping socket. In particular,
// Android VPN sockets must be protected before any packet is transmitted.
func (d *direct) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	var target net.IP
	var zone string
	if addr.IsFqdn() {
		ips, err := netapi.ResolverIP(ctx, addr.Hostname())
		if err != nil {
			return 0, err
		}
		target = ips.Rand()
	} else {
		a := addr.(netapi.IPAddress).AddrPort().Addr().Unmap()
		target = a.AsSlice()
		zone = a.Zone()
	}
	if len(target) == 0 {
		return 0, fmt.Errorf("ping %v: no IP address", addr)
	}

	network := "udp4"
	proto := 1
	requestType := ipv4.ICMPTypeEcho
	if target.To4() == nil {
		network = "udp6"
		proto = 58
		requestType = ipv6.ICMPTypeEchoRequest
	}

	iface := d.iface
	if iface == "" {
		iface = netapi.GetContext(ctx).ConnOptions().BindInterface()
	}
	if iface == "" {
		var err error
		iface, err = dialer.GetInterfaceByIP(target)
		if err != nil {
			return 0, err
		}
	} else if dialer.SkipInterface().Has(iface) {
		return 0, fmt.Errorf("ping %v: blocked interface %q", addr, iface)
	}

	ctx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()

	conn, err := icmp.ListenPacket(network, "")
	if err != nil {
		return 0, fmt.Errorf("ping %v: open ICMP socket: %w", addr, err)
	}
	defer conn.Close()

	if err := configurePingSocket(conn, network, iface, dialer.DefaultMarkSymbol); err != nil {
		return 0, fmt.Errorf("ping %v: configure ICMP socket: %w", addr, err)
	}

	dst := &net.UDPAddr{IP: target, Zone: zone}
	rtt, err := echoOnce(ctx, conn, dst, proto, requestType)
	if err != nil {
		return 0, fmt.Errorf("ping %v: %w", addr, err)
	}
	return uint64(rtt), nil
}

// ping sockets may have their ICMP identifier rewritten by the kernel.
// Match a random payload and sequence rather than depending on the Echo ID.
func echoOnce(ctx context.Context, conn net.PacketConn, dst *net.UDPAddr, proto int, requestType icmp.Type) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return 0, fmt.Errorf("generate ICMP token: %w", err)
	}
	seq := int(binary.BigEndian.Uint16(token[:2]))
	id := int(binary.BigEndian.Uint16(token[2:4]))
	msg := icmp.Message{
		Type: requestType,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: token[:]},
	}
	data, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return 0, err
		}
	}
	// ReadFrom must wake up immediately on cancellation, not merely on its deadline.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	sent := time.Now()
	if _, err := conn.WriteTo(data, dst); err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, err
	}
	var buf [2048]byte
	for {
		n, source, err := conn.ReadFrom(buf[:])
		if err != nil {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				return 0, err
			}
			return 0, fmt.Errorf("receive ICMP echo: %w", err)
		}
		received := time.Now()
		if matchesEchoReply(proto, buf[:n], source, dst, seq, token[:]) {
			return received.Sub(sent), nil
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}
}

func matchesEchoReply(proto int, packet []byte, src net.Addr, dst *net.UDPAddr, seq int, token []byte) bool {
	var srcIP net.IP
	var srcZone string
	switch a := src.(type) {
	case *net.UDPAddr:
		srcIP, srcZone = a.IP, a.Zone
	case *net.IPAddr:
		srcIP, srcZone = a.IP, a.Zone
	default:
		return false
	}
	if !srcIP.Equal(dst.IP) || (dst.Zone != "" && srcZone != "" && srcZone != dst.Zone) {
		return false
	}

	// Some Darwin ping sockets return the IPv4 header as part of ReadFrom.
	if proto == 1 && len(packet) >= 20 && packet[0]>>4 == 4 {
		hlen := int(packet[0]&0xf) * 4
		if hlen < 20 || hlen >= len(packet) || packet[9] != 1 {
			return false
		}
		packet = packet[hlen:]
	}

	msg, err := icmp.ParseMessage(proto, packet)
	if err != nil {
		return false
	}
	if proto == 1 && msg.Type != ipv4.ICMPTypeEchoReply ||
		proto == 58 && msg.Type != ipv6.ICMPTypeEchoReply {
		return false
	}
	echo, ok := msg.Body.(*icmp.Echo)
	return ok && echo.Seq == seq && bytes.Equal(echo.Data, token)
}

func configurePingSocket(conn *icmp.PacketConn, network, iface string, mark func(int32) bool) error {
	var pc net.PacketConn
	if network == "udp4" {
		pc = conn.IPv4PacketConn().PacketConn
	} else {
		pc = conn.IPv6PacketConn().PacketConn
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return errors.New("ICMP socket does not expose SyscallConn")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	err = raw.Control(func(fd uintptr) {
		optionErr = applyPingSocketOptions(network, fd, iface, mark)
	})
	if err != nil {
		return err
	}
	return optionErr
}

func applyPingSocketOptions(network string, fd uintptr, iface string, mark func(int32) bool) error {
	if iface != "" {
		if err := dialer.BindInterface(network, fd, iface); err != nil {
			return fmt.Errorf("bind to interface %q: %w", iface, err)
		}
	}
	if mark != nil && !mark(int32(fd)) {
		// On Android this is VpnService.protect(fd). Sending anyway can loop
		// the packet into our own TUN. Linux SO_MARK historically allows a
		// permission-denied fallback, so don't change that policy here.
		if runtime.GOOS == "android" {
			return errors.New("VpnService.protect failed")
		}
		log.Warn("ping socket mark failed", "interface", iface)
	}
	return nil
}
