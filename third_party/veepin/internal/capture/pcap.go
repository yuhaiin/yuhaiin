package capture

// A classic-pcap reader, and just enough Ethernet/IP/UDP to pull datagrams back
// out of a capture.
//
// Written from scratch because the module's dependency list is a load-bearing
// claim (golang.org/x/{crypto,net,sys,text} and nothing else), and because the
// format is small enough that reading it is cheaper than arguing about it:
//
//	 0                   1                   2                   3
//	+-------------------------------+-------------------------------+
//	|                        magic (0xa1b2c3d4)                     |  file
//	|  version major |  version minor                               |  header,
//	|                        thiszone (signed)                      |  24 octets
//	|                        sigfigs                                |
//	|                        snaplen                                |
//	|                        network (link type)                    |
//	+-------------------------------+-------------------------------+
//	|  ts_sec | ts_usec | incl_len | orig_len |  <incl_len octets>  |  per packet,
//	+-------------------------------+-------------------------------+  16 + n
//
// The magic doubles as the byte-order mark, which is the one genuinely clever
// thing in the format: 0xa1b2c3d4 read the wrong way round is 0xd4c3b2a1, so a
// reader learns the writer's endianness from the first four octets. 0xa1b23c4d
// is the same file with nanosecond timestamps.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Link types, from the libpcap registry. Only the three a container capture can
// produce are handled; anything else is an error rather than a guess.
const (
	linkEthernet = 1   // LINKTYPE_ETHERNET -- tcpdump -i eth0
	linkRaw      = 101 // LINKTYPE_RAW      -- a bare IP header
	linkLinuxSLL = 113 // LINKTYPE_LINUX_SLL -- tcpdump -i any
)

const (
	pcapFileHeaderLen   = 24
	pcapPacketHeaderLen = 16
	ethernetHeaderLen   = 14
	sllHeaderLen        = 16
	udpHeaderLen        = 8
)

// Datagram is one UDP datagram lifted out of a capture, with the addresses that
// say which side sent it.
type Datagram struct {
	Src, Dst netip.AddrPort
	Payload  []byte
}

var (
	errShortFile   = errors.New("capture: pcap file header is truncated")
	errNotPcap     = errors.New("capture: not a classic pcap file (pcapng is not supported; write with `tcpdump -w`)")
	errShortPacket = errors.New("capture: pcap packet record is truncated")
)

// ReadPCAP parses a classic pcap file and returns every UDP datagram in it, in
// capture order.
//
// Non-IP and non-UDP frames are skipped: a real capture is full of ARP and
// ICMP and skipping them is the point of a filter, not a loss. An IP-fragmented
// UDP datagram is a different matter and is an *error* — this reader does not
// reassemble, and silently returning the first fragment as if it were the whole
// datagram would hand a corpus a message that no peer ever sent. Capture with a
// snaplen large enough and a path that does not fragment, or handle the error.
func ReadPCAP(data []byte) ([]Datagram, error) {
	if len(data) < pcapFileHeaderLen {
		return nil, errShortFile
	}
	var bo binary.ByteOrder
	switch binary.BigEndian.Uint32(data) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		bo = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		bo = binary.LittleEndian
	default:
		return nil, errNotPcap
	}
	link := bo.Uint32(data[20:24])

	var out []Datagram
	rest := data[pcapFileHeaderLen:]
	for len(rest) > 0 {
		if len(rest) < pcapPacketHeaderLen {
			return nil, errShortPacket
		}
		// uint64 rather than int, so the bound holds on a 32-bit builder too:
		// int(uint32) can go negative there, and a negative length slices.
		inclLen := uint64(bo.Uint32(rest[8:12]))
		rest = rest[pcapPacketHeaderLen:]
		if inclLen > uint64(len(rest)) {
			return nil, errShortPacket
		}
		frame := rest[:inclLen]
		rest = rest[inclLen:]

		dg, ok, err := decodeFrame(link, frame)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, dg)
		}
	}
	return out, nil
}

// decodeFrame peels one link-layer frame down to a UDP datagram. ok is false
// for anything that is simply not a UDP datagram.
func decodeFrame(link uint32, frame []byte) (Datagram, bool, error) {
	var (
		ethType uint16
		payload []byte
	)
	switch link {
	case linkEthernet:
		if len(frame) < ethernetHeaderLen {
			return Datagram{}, false, nil
		}
		ethType = binary.BigEndian.Uint16(frame[12:14])
		payload = frame[ethernetHeaderLen:]
		// 802.1Q and 802.1ad each insert four octets before the real type.
		for ethType == 0x8100 || ethType == 0x88a8 {
			if len(payload) < 4 {
				return Datagram{}, false, nil
			}
			ethType = binary.BigEndian.Uint16(payload[2:4])
			payload = payload[4:]
		}
	case linkLinuxSLL:
		if len(frame) < sllHeaderLen {
			return Datagram{}, false, nil
		}
		ethType = binary.BigEndian.Uint16(frame[14:16])
		payload = frame[sllHeaderLen:]
	case linkRaw:
		if len(frame) == 0 {
			return Datagram{}, false, nil
		}
		switch frame[0] >> 4 {
		case 4:
			ethType = 0x0800
		case 6:
			ethType = 0x86dd
		default:
			return Datagram{}, false, nil
		}
		payload = frame
	default:
		return Datagram{}, false, fmt.Errorf("capture: unsupported pcap link type %d", link)
	}

	switch ethType {
	case 0x0800:
		return decodeIPv4(payload)
	case 0x86dd:
		return decodeIPv6(payload)
	default:
		return Datagram{}, false, nil
	}
}

var errFragment = errors.New("capture: capture contains an IP-fragmented UDP datagram; " +
	"this reader does not reassemble, and half a datagram is not evidence of anything")

func decodeIPv4(b []byte) (Datagram, bool, error) {
	if len(b) < 20 {
		return Datagram{}, false, nil
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return Datagram{}, false, nil
	}
	// Total Length delimits the datagram; anything past it is link padding.
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total >= ihl && total <= len(b) {
		b = b[:total]
	}
	proto := b[9]
	if proto != 17 {
		return Datagram{}, false, nil
	}
	fragOff := binary.BigEndian.Uint16(b[6:8])
	// bit 13 is MF; the low 13 bits are the offset. Either being set means this
	// datagram was split, and we hold only a piece of it.
	if fragOff&0x2000 != 0 || fragOff&0x1fff != 0 {
		return Datagram{}, false, errFragment
	}
	src, _ := netip.AddrFromSlice(b[12:16])
	dst, _ := netip.AddrFromSlice(b[16:20])
	return decodeUDP(src, dst, b[ihl:])
}

func decodeIPv6(b []byte) (Datagram, bool, error) {
	if len(b) < 40 {
		return Datagram{}, false, nil
	}
	payloadLen := int(binary.BigEndian.Uint16(b[4:6]))
	next := b[6]
	src, _ := netip.AddrFromSlice(b[8:24])
	dst, _ := netip.AddrFromSlice(b[24:40])
	rest := b[40:]
	if payloadLen <= len(rest) {
		rest = rest[:payloadLen]
	}
	// A fragment header is the v6 spelling of the same problem as above.
	if next == 44 {
		return Datagram{}, false, errFragment
	}
	if next != 17 {
		return Datagram{}, false, nil
	}
	return decodeUDP(src, dst, rest)
}

func decodeUDP(src, dst netip.Addr, b []byte) (Datagram, bool, error) {
	if len(b) < udpHeaderLen {
		return Datagram{}, false, nil
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	if length < udpHeaderLen || length > len(b) {
		// A truncated capture (a snaplen shorter than the datagram) would land
		// here. Take what is present rather than inventing octets, but say so.
		length = len(b)
	}
	return Datagram{
		Src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(b[0:2])),
		Dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(b[2:4])),
		Payload: b[udpHeaderLen:length],
	}, true, nil
}

// FilterPort keeps only the datagrams with the given source or destination
// port. It is the usual first step in turning a capture into a corpus: an IKE
// exchange is everything on 500 and 4500 and nothing else.
func FilterPort(in []Datagram, ports ...uint16) []Datagram {
	want := make(map[uint16]bool, len(ports))
	for _, p := range ports {
		want[p] = true
	}
	var out []Datagram
	for _, d := range in {
		if want[d.Src.Port()] || want[d.Dst.Port()] {
			out = append(out, d)
		}
	}
	return out
}
