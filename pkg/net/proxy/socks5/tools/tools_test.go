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
	z := ParseAddr(netapi.ParseAddressPort("", "a.com", 10051))
	t.Log(z)

	addr, err := ResolveAddr(bytes.NewReader(z))
	assert.NoError(t, err)
	t.Log(addr)
	t.Log(addr.Address(""))
}

func TestReadAddr(t *testing.T) {
	z := ParseAddr(netapi.ParseAddressPort("", "a.com", 10051))
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
	z := ParseAddr(netapi.ParseAddressPort("", "a.com", 10051))
	t.Log(z)
	z2 := ParseAddr(netapi.ParseIPAddr("", net.ParseIP("ff::ff"), 10051))

	for _, z := range []Addr{z, z2} {
		n, addr, err := DecodeAddr("", z)
		assert.NoError(t, err)
		t.Log(n, len(z))
		t.Log(addr)
	}
}
