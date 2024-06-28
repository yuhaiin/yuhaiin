package socks5

import (
	"bytes"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
)

func TestResolveAddr(t *testing.T) {
	port := uint16(443)

	x := tools.ParseAddr(netapi.ParseAddressPort("tcp", "www.baidu.com", port))
	t.Log(tools.ResolveAddr(bytes.NewBuffer(x)))

	x = tools.ParseAddr(netapi.ParseAddressPort("tcp", "127.0.0.1", port))
	// t.Log(x[0], x[1], x[2], x[3], x[4], x[3:], x[:3], x[:])
	t.Log(tools.ResolveAddr(bytes.NewBuffer(x)))

	x = tools.ParseAddr(netapi.ParseAddressPort("tcp", "[ff::ff]", port))
	t.Log(tools.ResolveAddr(bytes.NewBuffer(x)))
}
