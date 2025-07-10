package socks5

import (
	"bytes"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestResolveAddr(t *testing.T) {
	port := uint16(443)

	addr, err := netapi.ParseAddressPort("tcp", "www.baidu.com", port)
	assert.NoError(t, err)
	x := tools.ParseAddr(addr)
	t.Log(tools.ResolveAddr(bytes.NewBuffer(x)))

	addr, err = netapi.ParseAddressPort("tcp", "127.0.0.1", port)
	assert.NoError(t, err)
	x = tools.ParseAddr(addr)
	// t.Log(x[0], x[1], x[2], x[3], x[4], x[3:], x[:3], x[:])
	t.Log(tools.ResolveAddr(bytes.NewBuffer(x)))

	addr, err = netapi.ParseAddressPort("tcp", "[ff::ff]", port)
	x = tools.ParseAddr(addr)
	t.Log(tools.ResolveAddr(bytes.NewBuffer(x)))
}
