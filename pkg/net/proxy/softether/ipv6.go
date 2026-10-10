package softether

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/softether/native"
)

const etherIPv6 = 0x86dd

func ipv6MulticastMAC(addr netip.Addr) macAddr {
	a := addr.As16()
	return macAddr{0x33, 0x33, a[12], a[13], a[14], a[15]}
}

func solicitedNodeMulticast(target netip.Addr) netip.Addr {
	a := target.As16()
	return netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, a[13], a[14], a[15]})
}

// icmpv6Checksum covers the IPv6 pseudoheader and ICMPv6 message.
func icmpv6Checksum(src, dst netip.Addr, msg []byte) uint16 {
	pseudo := make([]byte, 40+len(msg))
	s, d := src.As16(), dst.As16()
	copy(pseudo[:16], s[:])
	copy(pseudo[16:32], d[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(msg)))
	pseudo[39] = 58
	copy(pseudo[40:], msg)
	return ipChecksum(pseudo)
}

func makeIPv6Packet(src, dst netip.Addr, proto byte, hopLimit byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6], packet[7] = proto, hopLimit
	s, d := src.As16(), dst.As16()
	copy(packet[8:24], s[:])
	copy(packet[24:40], d[:])
	copy(packet[40:], payload)
	return packet
}

func neighborSolicit(mac macAddr, src, target netip.Addr) []byte {
	dst := solicitedNodeMulticast(target)
	icmp := make([]byte, 32)
	icmp[0] = 135
	t := target.As16()
	copy(icmp[8:24], t[:])
	icmp[24], icmp[25] = 1, 1 // source link-layer address
	copy(icmp[26:32], mac[:])
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(src, dst, icmp))
	return ethernetFrame(ipv6MulticastMAC(dst), mac, etherIPv6, makeIPv6Packet(src, dst, 58, 255, icmp))
}

func neighborAdvertise(mac, dstMAC macAddr, local, peer netip.Addr) []byte {
	icmp := make([]byte, 32)
	icmp[0], icmp[4] = 136, 0x60 // solicited and override
	a := local.As16()
	copy(icmp[8:24], a[:])
	icmp[24], icmp[25] = 2, 1 // target link-layer address
	copy(icmp[26:32], mac[:])
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(local, peer, icmp))
	return ethernetFrame(dstMAC, mac, etherIPv6, makeIPv6Packet(local, peer, 58, 255, icmp))
}

func parseNeighborMessage(frame []byte) (typ byte, target, src, dst netip.Addr, from macAddr, ok bool) {
	if len(frame) < 14+40+24 || binary.BigEndian.Uint16(frame[12:14]) != etherIPv6 {
		return
	}
	copy(from[:], frame[6:12])
	ip := frame[14:]
	if ip[0]>>4 != 6 || ip[6] != 58 || ip[7] != 255 {
		return
	}
	size := int(binary.BigEndian.Uint16(ip[4:6]))
	if size < 24 || len(ip) < 40+size {
		return
	}
	src = netip.AddrFrom16([16]byte(ip[8:24]))
	dst = netip.AddrFrom16([16]byte(ip[24:40]))
	icmp := ip[40 : 40+size]
	if icmp[1] != 0 {
		return
	}
	if icmp[0] != 135 && icmp[0] != 136 {
		return
	}
	typ = icmp[0]
	target = netip.AddrFrom16([16]byte(icmp[8:24]))
	if icmpv6Checksum(src, dst, icmp) != 0 {
		return
	}
	return typ, target, src, dst, from, true
}

func resolveIPv6Router(session *native.ClientSession, mac macAddr, local, router netip.Addr, timeout time.Duration) (macAddr, error) {
	if !local.Is6() || !router.Is6() {
		return macAddr{}, errors.New("softether: missing IPv6 router/address")
	}
	if err := session.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return macAddr{}, err
	}
	defer func() { _ = session.SetReadDeadline(time.Time{}) }()
	if err := session.WriteFrame(neighborSolicit(mac, local, router)); err != nil {
		return macAddr{}, err
	}
	for {
		frame, err := session.ReadFrame()
		if err != nil {
			return macAddr{}, fmt.Errorf("softether: IPv6 router neighbor discovery: %w", err)
		}
		kind, target, src, _, from, ok := parseNeighborMessage(frame)
		if !ok {
			continue
		}
		if kind == 136 && target == router && src == router && from != (macAddr{}) {
			return from, nil
		}
		if kind == 135 && target == local && src.Is6() && !src.IsUnspecified() {
			_ = session.WriteFrame(neighborAdvertise(mac, from, local, src))
		}
	}
}
