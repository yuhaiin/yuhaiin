package peerrendezvous

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

const stunCookie = 0x2112A442

// stunClient sends RFC 5389 binding requests from the hub's own socket, so the
// mapped address is the one peers must use to reach the hub.
type stunClient struct {
	socket net.PacketConn
	mu     sync.Mutex
	txn    [12]byte
	result chan netip.AddrPort
}

func newSTUNClient(socket net.PacketConn) *stunClient {
	return &stunClient{socket: socket, result: make(chan netip.AddrPort, 1)}
}

func (s *stunClient) close() {}

func (s *stunClient) query(server netip.AddrPort, timeout time.Duration) (netip.AddrPort, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rand.Read(s.txn[:])
	select {
	case <-s.result:
	default:
	}
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:], 0x0001)
	binary.BigEndian.PutUint32(request[4:], stunCookie)
	copy(request[8:], s.txn[:])
	deadline := time.After(timeout)
	retry := time.NewTicker(500 * time.Millisecond)
	defer retry.Stop()
	for {
		if _, err := s.socket.WriteTo(request, net.UDPAddrFromAddrPort(server)); err != nil {
			return netip.AddrPort{}, err
		}
		select {
		case ap := <-s.result:
			return ap, nil
		case <-retry.C:
		case <-deadline:
			return netip.AddrPort{}, errors.New("STUN: no response")
		}
	}
}

// receive consumes a binding response for the outstanding request.
func (s *stunClient) receive(p []byte, from netip.AddrPort) bool {
	if len(p) < 20 || binary.BigEndian.Uint32(p[4:8]) != stunCookie || p[0]&0xc0 != 0 {
		return false
	}
	if binary.BigEndian.Uint16(p[0:2]) != 0x0101 {
		return true
	}
	if string(p[8:20]) != string(s.txn[:]) {
		return true
	}
	body := p[20:min(len(p), 20+int(binary.BigEndian.Uint16(p[2:4])))]
	for len(body) >= 4 {
		typ, n := binary.BigEndian.Uint16(body), int(binary.BigEndian.Uint16(body[2:]))
		if len(body) < 4+n {
			break
		}
		value := body[4 : 4+n]
		if typ == 0x0020 && n >= 8 { // XOR-MAPPED-ADDRESS
			port := binary.BigEndian.Uint16(value[2:]) ^ uint16(stunCookie>>16)
			var ip netip.Addr
			switch value[1] {
			case 1:
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], binary.BigEndian.Uint32(value[4:])^stunCookie)
				ip = netip.AddrFrom4(b)
			case 2:
				if n >= 20 {
					var b [16]byte
					copy(b[:], value[4:20])
					var mask [16]byte
					binary.BigEndian.PutUint32(mask[:], stunCookie)
					copy(mask[4:], p[8:20])
					for i := range b {
						b[i] ^= mask[i]
					}
					ip = netip.AddrFrom16(b)
				}
			}
			if ip.IsValid() {
				select {
				case s.result <- netip.AddrPortFrom(ip.Unmap(), port):
				default:
				}
			}
			return true
		}
		body = body[4+(n+3)&^3:]
	}
	return true
}
