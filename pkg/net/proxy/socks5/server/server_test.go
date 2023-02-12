package server

import (
	"bytes"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

func TestResolveAddr(t *testing.T) {
	port := proxy.ParsePort(443)

	x := s5c.ParseAddr(proxy.ParseAddressPort(statistic.Type_tcp, "www.baidu.com", port))
	t.Log(s5c.ResolveAddr(bytes.NewBuffer(x)))

	x = s5c.ParseAddr(proxy.ParseAddressPort(statistic.Type_tcp, "127.0.0.1", port))
	t.Log(x[0], x[1], x[2], x[3], x[4], x[3:], x[:3], x[:])
	t.Log(s5c.ResolveAddr(bytes.NewBuffer(x)))

	x = s5c.ParseAddr(proxy.ParseAddressPort(statistic.Type_tcp, "[ff::ff]", port))
	t.Log(s5c.ResolveAddr(bytes.NewBuffer(x)))
}
