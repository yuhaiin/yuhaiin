package lightweight

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

func TestIPv6AndTransportValidation(t *testing.T) {
	src, dst := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	udp := []byte{0, 53, 0, 80, 0, 8, 0, 0}
	valid := bytes.Clone(udp)
	binary.BigEndian.PutUint16(valid[6:8], transportChecksum(src, dst, 17, valid))
	for _, tc := range []struct {
		name    string
		proto   byte
		payload []byte
		wantErr bool
	}{
		{"UDP", 17, valid, false}, {"UDP zero", 17, udp, true}, {"UDP length mismatch", 17, append(bytes.Clone(valid), 1), true},
		{"extension padding", 0, append([]byte{17, 0, 0, 0, 0, 0, 0, 0}, valid...), false},
		{"extension length", 0, []byte{17, 255, 0, 0, 0, 0, 0, 0}, true},
		{"routing nonzero segments left", 43, append([]byte{17, 0, 0, 1, 0, 0, 0, 0}, valid...), true},
		{"TCP offset underflow", 6, make([]byte, 20), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := makeIP(src, dst, tc.proto, tc.payload, 1)
			if err != nil {
				t.Fatal(err)
			}
			p, err := ParsePacket(b)
			if err == nil {
				err = p.ValidateTransport()
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("error: %v", err)
			}
		})
	}
	for _, version := range []byte{0, 1, 3, 7, 15} {
		if _, err := ParsePacket([]byte{version << 4}); err == nil {
			t.Fatal("invalid version")
		}
	}
}

func fragmentedV4(id uint16, off int, more bool, payload []byte) []byte {
	b, _ := makeIP(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"), 17, payload, id)
	f := uint16(off / 8)
	if more {
		f |= 0x2000
	}
	binary.BigEndian.PutUint16(b[6:8], f)
	b[10] = 0
	b[11] = 0
	binary.BigEndian.PutUint16(b[10:12], Checksum(b[:20]))
	return b
}
func TestFragmentOverlapExpiryAndLimits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := memoryPair()
		s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, MaxFragmentGroups: 1, FragmentTimeout: time.Second}, a)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		send := func(p []byte) { _ = b.WritePacket(p); synctest.Wait() }
		send(fragmentedV4(1, 0, true, make([]byte, 8)))
		first := s.Stats().MemoryBytes
		if first <= 8 || first > 4096 {
			t.Fatal("fragment not cached within budget")
		}
		send(fragmentedV4(2, 0, true, make([]byte, 8)))
		if s.Stats().MemoryBytes != first || s.Stats().Drops != 1 {
			t.Fatal("fragment group bound")
		}
		send(fragmentedV4(1, 0, true, make([]byte, 8)))
		poisoned := s.Stats().MemoryBytes
		if poisoned >= first {
			t.Fatal("overlap did not discard group")
		}
		send(fragmentedV4(1, 8, false, make([]byte, 8)))
		if s.Stats().MemoryBytes != poisoned {
			t.Fatal("poisoned group was revived")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		send(fragmentedV4(2, 0, true, make([]byte, 8)))
		if s.Stats().MemoryBytes != first {
			t.Fatal("expired slot not reusable")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if s.Stats().MemoryBytes != 0 {
			t.Fatal("fragment expiry retained bytes")
		}
	})
}

func TestUDPFragmentationRoundTrip(t *testing.T) {
	a, b := stackPair(t)
	for _, addr := range []string{"192.0.2.2:9000", "[2001:db8::2]:9000"} {
		dst := netip.MustParseAddrPort(addr)
		u, err := b.ListenUDP(dst)
		if err != nil {
			t.Fatal(err)
		}
		c, err := a.DialUDP(netip.AddrPort{}, dst)
		if err != nil {
			t.Fatal(err)
		}
		_ = u.SetReadDeadline(time.Now().Add(time.Second))
		payload := bytes.Repeat([]byte{0, 255, 10}, 20000)
		if _, err = c.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 65535)
		n, _, err := u.ReadFrom(got)
		if err != nil || !bytes.Equal(payload, got[:n]) {
			t.Fatalf("fragment reassembly %d: %v", n, err)
		}
		_ = c.Close()
		_ = u.Close()
	}
}
func FuzzTCPOptions(f *testing.F) {
	f.Add([]byte{2, 4, 5, 180})
	f.Add([]byte{5, 10, 0, 0, 0, 1, 0, 0, 0, 2})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 40 {
			b = b[:40]
		}
		_, _ = parseTCPOptions(b)
	})
}
