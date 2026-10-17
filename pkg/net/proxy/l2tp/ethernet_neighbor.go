package l2tp

import (
	"encoding/binary"
	"net/netip"
)

func (n *ethernetNetwork) solicit(ip netip.Addr) {
	src := n.source(ip)
	if !src.IsValid() {
		return
	}
	if ip.Is4() {
		n.arp(1, [6]byte{255, 255, 255, 255, 255, 255}, src, ip)
		return
	}
	a := ip.As16()
	dst := netip.AddrFrom16([16]byte{0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, a[13], a[14], a[15]})
	msg := make([]byte, 32)
	msg[0] = 135
	copy(msg[8:24], a[:])
	msg[24], msg[25] = 1, 1
	copy(msg[26:], n.mac[:])
	n.ndp(src, dst, [6]byte{0x33, 0x33, 0xff, a[13], a[14], a[15]}, msg)
}
func (n *ethernetNetwork) arp(op uint16, dst [6]byte, src, target netip.Addr) {
	b := make([]byte, 28)
	binary.BigEndian.PutUint16(b, 1)
	binary.BigEndian.PutUint16(b[2:], 0x0800)
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:], op)
	copy(b[8:14], n.mac[:])
	s, d := src.As4(), target.As4()
	copy(b[14:18], s[:])
	if op == 2 {
		copy(b[18:24], dst[:])
	}
	copy(b[24:28], d[:])
	n.queueFrame(dst, 0x0806, b)
}
func (n *ethernetNetwork) handleARP(f []byte) {
	if len(f) < 42 {
		return
	}
	b := f[14:42]
	if binary.BigEndian.Uint16(b) != 1 || binary.BigEndian.Uint16(b[2:]) != 0x0800 || b[4] != 6 || b[5] != 4 {
		return
	}
	mac := [6]byte(b[8:14])
	if mac != [6]byte(f[6:12]) || mac[0]&1 != 0 {
		return
	}
	src, dst := netip.AddrFrom4([4]byte(b[14:18])), netip.AddrFrom4([4]byte(b[24:28]))
	if !n.local(dst) {
		return
	}
	switch binary.BigEndian.Uint16(b[6:8]) {
	case 1:
		n.learn(src, mac)
		n.arp(2, mac, dst, src)
	case 2:
		if [6]byte(b[18:24]) == n.mac {
			n.learn(src, mac)
		}
	}
}
func ethernetChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func ndpChecksum(src, dst netip.Addr, b []byte) uint16 {
	pseudo := make([]byte, 40+len(b))
	s, d := src.As16(), dst.As16()
	copy(pseudo, s[:])
	copy(pseudo[16:], d[:])
	binary.BigEndian.PutUint32(pseudo[32:], uint32(len(b)))
	pseudo[39] = 58
	copy(pseudo[40:], b)
	return ethernetChecksum(pseudo)
}
func (n *ethernetNetwork) ndp(src, dst netip.Addr, mac [6]byte, msg []byte) {
	binary.BigEndian.PutUint16(msg[2:], ndpChecksum(src, dst, msg))
	b := make([]byte, 40+len(msg))
	b[0], b[6], b[7] = 0x60, 58, 255
	binary.BigEndian.PutUint16(b[4:], uint16(len(msg)))
	s, d := src.As16(), dst.As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	copy(b[40:], msg)
	n.queueFrame(mac, 0x86dd, b)
}

// handleNDP consumes neighbor messages so they never enter the IP transport
// stack. RFC 4861's hop limit, checksum, target and option checks precede use.
func (n *ethernetNetwork) handleNDP(f []byte) bool {
	if len(f) < 14+40+1 || f[14]>>4 != 6 || f[20] != 58 || f[54] != 135 && f[54] != 136 {
		return false
	}
	ip := f[14:]
	size := int(binary.BigEndian.Uint16(ip[4:]))
	if ip[7] != 255 || size < 24 || size > len(ip)-40 {
		return true
	}
	src, dst := netip.AddrFrom16([16]byte(ip[8:24])), netip.AddrFrom16([16]byte(ip[24:40]))
	msg := ip[40 : 40+size]
	target := netip.AddrFrom16([16]byte(msg[8:24]))
	if msg[1] != 0 || target.IsMulticast() || target.IsUnspecified() || src.IsMulticast() || ndpChecksum(src, dst, msg) != 0 {
		return true
	}
	mac := [6]byte(f[6:12])
	if mac[0]&1 != 0 || mac == ([6]byte{}) {
		return true
	}
	var linkOption bool
	for opts := msg[24:]; len(opts) > 0; {
		if len(opts) < 2 || opts[1] == 0 || int(opts[1])*8 > len(opts) {
			return true
		}
		size := int(opts[1]) * 8
		if opts[0] == 1 || opts[0] == 2 {
			if size != 8 || [6]byte(opts[2:8]) != mac {
				return true
			}
			if msg[0] == 135 && opts[0] == 1 {
				linkOption = true
			}
		}
		opts = opts[size:]
	}
	if msg[0] == 136 {
		if src.IsUnspecified() || msg[4]&0x40 != 0 && dst.IsMulticast() {
			return true
		}
		if !n.local(dst) {
			return true
		}
		n.learn(target, mac)
		return true
	}
	if !n.local(target) {
		return true
	}
	if src.IsUnspecified() && linkOption {
		return true
	}
	n.learn(src, mac)
	reply := make([]byte, 32)
	reply[0], reply[4] = 136, 0x60
	a := target.As16()
	copy(reply[8:24], a[:])
	reply[24], reply[25] = 2, 1
	copy(reply[26:], n.mac[:])
	if src.IsUnspecified() {
		src = netip.MustParseAddr("ff02::1")
		mac = [6]byte{0x33, 0x33, 0, 0, 0, 1}
		reply[4] = 0x20
	}
	n.ndp(target, src, mac, reply)
	return true
}
