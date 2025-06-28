package resolver

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/miekg/dns"
)

func GetECHConfig(msg dns.SVCB) ([]tls.ECHConfigSpec, error) {
	for _, v := range msg.Value {
		if v.Key() == dns.SVCB_ECHCONFIG {
			return tls.ParseECHConfigList(v.(*dns.SVCBECHConfig).ECH)
		}
	}

	return nil, fmt.Errorf("echconfig not found")
}
