package latency

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
)

func TestIP(t *testing.T) {
	x := &Protocol_Ip{
		Ip: &Ip{
			Url:       "http://ip.sb",
			UserAgent: "curl/7.54.1",
		},
	}

	r, err := x.Latency(direct.Default)
	t.Log(r, err)
}
