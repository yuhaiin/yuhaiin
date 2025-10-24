package tools

import (
	"bufio"
	"bytes"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestResolveAddr(t *testing.T) {
	md, err := netapi.ParseAddressPort("", "a.com", 10051)
	assert.NoError(t, err)
	z := ParseAddr(md)
	t.Log(z)

	addr, err := ResolveAddr(bytes.NewReader(z))
	assert.NoError(t, err)
	t.Log(addr)
	t.Log(addr.Address(""))
}

func TestReadAddr(t *testing.T) {
	md, err := netapi.ParseAddressPort("", "a.com", 10051)
	assert.NoError(t, err)
	z := ParseAddr(md)
	t.Log(z)
	z2 := ParseAddr(netapi.ParseIPAddr("", net.ParseIP("ff::ff"), 10051))

	for _, z := range []Addr{z, z2} {
		n, addr, err := ReadAddr("", bufio.NewReader(bytes.NewReader(z)))
		assert.NoError(t, err)
		t.Log(n, len(z))
		t.Log(addr)
	}
}

func TestDecodeAddr(t *testing.T) {
	md, err := netapi.ParseAddressPort("", "a.com", 10051)
	assert.NoError(t, err)
	z := ParseAddr(md)
	t.Log(z)
	z2 := ParseAddr(netapi.ParseIPAddr("", net.ParseIP("ff::ff"), 10051))

	for _, z := range []Addr{z, z2} {
		n, addr, err := DecodeAddr("", z)
		assert.NoError(t, err)
		t.Log(n, len(z))
		t.Log(addr)
	}
}

func FuzzDecodeAddr(f *testing.F) {
	buf := make([]byte, 1024)
	n := EncodeAddr(netapi.ParseIPAddr("", net.ParseIP("ff::ff"), 10051), buf)

	f.Add(buf[:n])

	buf2 := make([]byte, 1024)
	copy(buf2, buf[:n])
	buf[0] = Domain
	f.Add(buf2[:n])

	buf3 := make([]byte, 1024)
	copy(buf3, buf[:n])
	buf[0] = IPv4
	f.Add(buf3[:n])

	buf4 := make([]byte, 1024)
	n = EncodeAddr(netapi.ParseIPAddr("", net.ParseIP("127.0.0.1"), 100), buf)
	f.Add(buf4[:n])

	buf5 := make([]byte, 1024)
	copy(buf5, buf[:n])
	f.Add(buf5[:n-4])
	f.Add([]byte{})

	buf6 := make([]byte, 1024)
	addr, err := netapi.ParseAddressPort("", "a.com", 10051)
	assert.NoError(f, err)
	n = EncodeAddr(addr, buf)
	f.Add(buf6[:n])

	buf7 := make([]byte, 1024)
	copy(buf7, buf[:n])
	buf7[0] = IPv6
	f.Add(buf)

	buf8 := make([]byte, 1024)
	copy(buf8, buf[:n])
	buf8[0] ^= 0x55
	f.Add(buf8)

	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeAddr("", data)
	})
}
