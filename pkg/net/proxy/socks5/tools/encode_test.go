package tools

import (
	"bytes"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"net"
	"testing"
)

type customAddr string

func (customAddr) Network() string  { return "udp" }
func (a customAddr) String() string { return string(a) }

func TestEncodeSysAddrMatchesAddressEncoding(t *testing.T) {
	domain, _ := netapi.ParseDomainPort("udp", "example.com", 5353)
	for _, addr := range []net.Addr{
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5353},
		&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 65535},
		&net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 1},
		&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 53, Zone: "eth0"},
		&net.UDPAddr{Port: 0}, &net.UDPAddr{IP: net.IP{1, 2}, Port: 53},
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443},
		&net.IPAddr{IP: net.ParseIP("2001:db8::1")},
		&net.UnixAddr{Name: "socket", Net: "unix"},
		domain, customAddr("custom.example:1234"),
	} {
		t.Run(addr.String(), func(t *testing.T) {
			var actual, expected [MaxAddrLength]byte
			parsed, err := netapi.ParseSysAddr(addr)
			if err != nil {
				t.Fatal(err)
			}
			want := EncodeAddr(parsed, expected[:])
			got, err := EncodeSysAddr(addr, actual[:])
			if err != nil {
				t.Fatal(err)
			}
			if got != want || !bytes.Equal(actual[:got], expected[:want]) {
				t.Fatalf("encoding %x != %x", actual[:got], expected[:want])
			}
		})
	}
	for _, addr := range []net.Addr{nil, customAddr("host:invalid"), (*net.UDPAddr)(nil)} {
		var buf [MaxAddrLength]byte
		if _, err := EncodeSysAddr(addr, buf[:]); err == nil {
			t.Fatal("invalid address accepted")
		}
	}
}
