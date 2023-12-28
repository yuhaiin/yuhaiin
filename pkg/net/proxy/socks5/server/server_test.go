package server

import (
	"bytes"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

func TestResolveAddr(t *testing.T) {
	port := netapi.ParsePort(443)

	x := tools.ParseAddr(netapi.ParseAddressPort(statistic.Type_tcp, "www.baidu.com", port))
	t.Log(tools.ResolveAddr(bytes.NewBuffer(x)))

	x = tools.ParseAddr(netapi.ParseAddressPort(statistic.Type_tcp, "127.0.0.1", port))
	t.Log(x[0], x[1], x[2], x[3], x[4], x[3:], x[:3], x[:])
	t.Log(tools.ResolveAddr(bytes.NewBuffer(x)))

	x = tools.ParseAddr(netapi.ParseAddressPort(statistic.Type_tcp, "[ff::ff]", port))
	t.Log(tools.ResolveAddr(bytes.NewBuffer(x)))
}
