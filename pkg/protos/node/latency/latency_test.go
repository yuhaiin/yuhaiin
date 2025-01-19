package latency

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"google.golang.org/protobuf/proto"
)

func TestIP(t *testing.T) {
	x := (&Ip_builder{
		Url:       proto.String("http://ip.sb"),
		UserAgent: proto.String("curl/7.54.1"),
	}).Build()

	p := Protocol_builder{
		Ip: x,
	}.Build()

	r, err := p.Latency(direct.Default)
	t.Log(r, err)
}
