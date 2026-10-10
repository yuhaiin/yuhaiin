package softether

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/softether/native"
)

const (
	etherIPv4        = 0x0800
	etherARP         = 0x0806
	maxEthernetFrame = 3200
)

type macAddr [6]byte

type lease struct {
	ip     netip.Addr
	router netip.Addr
	mask   int
	server netip.Addr
}

func randomMAC() (macAddr, error) {
	var m macAddr
	if _, err := rand.Read(m[:]); err != nil {
		return m, err
	}
	m[0] = (m[0] | 2) &^ byte(1) // locally administered unicast
	return m, nil
}

func ethernetFrame(dst, src macAddr, ethertype uint16, payload []byte) []byte {
	b := make([]byte, 14+len(payload))
	copy(b[:6], dst[:])
	copy(b[6:12], src[:])
	binary.BigEndian.PutUint16(b[12:14], ethertype)
	copy(b[14:], payload)
	return b
}

func buildARP(mac macAddr, srcIP, targetIP netip.Addr, dst macAddr, op uint16) []byte {
	var b [28]byte
	binary.BigEndian.PutUint16(b[:2], 1) // Ethernet
	binary.BigEndian.PutUint16(b[2:4], etherIPv4)
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:8], op)
	copy(b[8:14], mac[:])
	src := srcIP.As4()
	copy(b[14:18], src[:])
	copy(b[18:24], dst[:])
	target := targetIP.As4()
	copy(b[24:28], target[:])
	if op == 1 {
		return ethernetFrame(macAddr{255, 255, 255, 255, 255, 255}, mac, etherARP, b[:])
	}
	return ethernetFrame(dst, mac, etherARP, b[:])
}

func parseARP(frame []byte) (op uint16, mac macAddr, sender, target netip.Addr, ok bool) {
	if len(frame) < 42 || binary.BigEndian.Uint16(frame[12:14]) != etherARP {
		return
	}
	b := frame[14:]
	if binary.BigEndian.Uint16(b[:2]) != 1 || binary.BigEndian.Uint16(b[2:4]) != etherIPv4 || b[4] != 6 || b[5] != 4 {
		return
	}
	op = binary.BigEndian.Uint16(b[6:8])
	copy(mac[:], b[8:14])
	sender = netip.AddrFrom4([4]byte{b[14], b[15], b[16], b[17]})
	target = netip.AddrFrom4([4]byte{b[24], b[25], b[26], b[27]})
	return op, mac, sender, target, true
}

func ipChecksum(p []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(p); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	if len(p)%2 == 1 {
		sum += uint32(p[len(p)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

// DHCP is deliberately done before attaching the user-mode IP stack. SoftEther
// native sessions transport Ethernet, not an assigned tunnel IP.
func buildDHCP(mac macAddr, xid uint32, typ byte, requested, server netip.Addr) []byte {
	payload := make([]byte, 240)
	payload[0], payload[1], payload[2] = 1, 1, 6
	binary.BigEndian.PutUint32(payload[4:8], xid)
	binary.BigEndian.PutUint16(payload[10:12], 0x8000) // broadcast flag
	copy(payload[28:34], mac[:])
	copy(payload[236:240], []byte{99, 130, 83, 99})
	payload = append(payload, 53, 1, typ)
	if typ == 3 && requested.Is4() && server.Is4() {
		ip, sv := requested.As4(), server.As4()
		payload = append(payload, 50, 4)
		payload = append(payload, ip[:]...)
		payload = append(payload, 54, 4)
		payload = append(payload, sv[:]...)
	}
	payload = append(payload, 55, 4, 1, 3, 6, 54, 255)
	if len(payload) < 300 {
		payload = append(payload, make([]byte, 300-len(payload))...)
	}
	udpLen := 8 + len(payload)
	ipLen := 20 + udpLen
	b := make([]byte, ipLen)
	b[0], b[8], b[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(b[2:4], uint16(ipLen))
	copy(b[16:20], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(b[10:12], ipChecksum(b[:20]))
	binary.BigEndian.PutUint16(b[20:22], 68)
	binary.BigEndian.PutUint16(b[22:24], 67)
	binary.BigEndian.PutUint16(b[24:26], uint16(udpLen))
	copy(b[28:], payload)
	return ethernetFrame(macAddr{255, 255, 255, 255, 255, 255}, mac, etherIPv4, b)
}

func parseDHCP(frame []byte, mac macAddr, xid uint32) (msg byte, l lease, ok bool) {
	if len(frame) < 14+20+8+240 || binary.BigEndian.Uint16(frame[12:14]) != etherIPv4 {
		return
	}
	ip := frame[14:]
	if ip[0]>>4 != 4 {
		return
	}
	ihl := int(ip[0]&15) * 4
	if ihl < 20 || len(ip) < ihl+8+240 || ip[9] != 17 {
		return
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total < ihl+8+240 || total > len(ip) {
		return
	}
	if binary.BigEndian.Uint16(ip[ihl:ihl+2]) != 67 || binary.BigEndian.Uint16(ip[ihl+2:ihl+4]) != 68 {
		return
	}
	udpLen := int(binary.BigEndian.Uint16(ip[ihl+4 : ihl+6]))
	if udpLen < 8+240 || ihl+udpLen > total {
		return
	}
	d := ip[ihl+8 : ihl+udpLen]
	if d[0] != 2 || d[1] != 1 || d[2] != 6 || binary.BigEndian.Uint32(d[4:8]) != xid {
		return
	}
	for i := range 6 {
		if d[28+i] != mac[i] {
			return
		}
	}
	if string(d[236:240]) != string([]byte{99, 130, 83, 99}) {
		return
	}
	l.ip = netip.AddrFrom4([4]byte{d[16], d[17], d[18], d[19]})
	var mask net.IPMask
	for i := 240; i < len(d); {
		tag := d[i]
		i++
		if tag == 255 {
			break
		}
		if tag == 0 {
			continue
		}
		if i >= len(d) || i+1+int(d[i]) > len(d) {
			return 0, lease{}, false
		}
		size := int(d[i])
		i++
		v := d[i : i+size]
		i += size
		switch tag {
		case 53:
			if len(v) == 1 {
				msg = v[0]
			}
		case 1:
			if len(v) == 4 {
				mask = net.IPMask(v)
			}
		case 3:
			if len(v) >= 4 {
				l.router = netip.AddrFrom4([4]byte{v[0], v[1], v[2], v[3]})
			}
		case 54:
			if len(v) == 4 {
				l.server = netip.AddrFrom4([4]byte{v[0], v[1], v[2], v[3]})
			}
		}
	}
	l.mask = 32
	if len(mask) == 4 {
		ones, bits := mask.Size()
		if bits != 32 {
			return 0, lease{}, false
		}
		l.mask = ones
	}
	return msg, l, msg != 0 && l.ip.Is4()
}

func negotiateDHCP(s *native.ClientSession, mac macAddr, timeout time.Duration) (lease, error) {
	var xid [4]byte
	if _, err := rand.Read(xid[:]); err != nil {
		return lease{}, err
	}
	id := binary.BigEndian.Uint32(xid[:])
	deadline := time.Now().Add(timeout)
	if err := s.SetReadDeadline(deadline); err != nil {
		return lease{}, err
	}
	defer func() { _ = s.SetReadDeadline(time.Time{}) }()
	if err := s.WriteFrame(buildDHCP(mac, id, 1, netip.Addr{}, netip.Addr{})); err != nil {
		return lease{}, err
	}
	var offer lease
	for {
		frame, err := s.ReadFrame()
		if err != nil {
			return lease{}, fmt.Errorf("softether: DHCP offer: %w", err)
		}
		kind, l, ok := parseDHCP(frame, mac, id)
		if !ok || kind != 2 || !l.server.Is4() {
			continue
		}
		offer = l
		break
	}
	if err := s.WriteFrame(buildDHCP(mac, id, 3, offer.ip, offer.server)); err != nil {
		return lease{}, err
	}
	for {
		frame, err := s.ReadFrame()
		if err != nil {
			return lease{}, fmt.Errorf("softether: DHCP ack: %w", err)
		}
		kind, l, ok := parseDHCP(frame, mac, id)
		if !ok {
			continue
		}
		if kind == 6 {
			return lease{}, errors.New("softether: DHCP rejected the lease")
		}
		if kind != 5 || l.ip != offer.ip {
			continue
		}
		if !l.router.Is4() {
			l.router = offer.router
		}
		if !l.router.Is4() {
			return lease{}, errors.New("softether: DHCP did not advertise an IPv4 router")
		}
		return l, nil
	}
}

func resolveGateway(s *native.ClientSession, mac macAddr, local, router netip.Addr, timeout time.Duration) (macAddr, error) {
	deadline := time.Now().Add(timeout)
	if err := s.SetReadDeadline(deadline); err != nil {
		return macAddr{}, err
	}
	defer func() { _ = s.SetReadDeadline(time.Time{}) }()
	if err := s.WriteFrame(buildARP(mac, local, router, macAddr{}, 1)); err != nil {
		return macAddr{}, err
	}
	for {
		frame, err := s.ReadFrame()
		if err != nil {
			return macAddr{}, fmt.Errorf("softether: ARP router %s: %w", router, err)
		}
		op, from, src, dst, ok := parseARP(frame)
		if ok && op == 2 && src == router && dst == local && from != (macAddr{}) {
			return from, nil
		}
		// We may receive an ARP question for our IP while resolving the router.
		if ok && op == 1 && dst == local {
			_ = s.WriteFrame(buildARP(mac, local, src, from, 2))
		}
	}
}
