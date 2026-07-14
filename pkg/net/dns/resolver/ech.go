package resolver

import (
	"fmt"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
)

func GetECHConfig(msg dns.SVCB) ([]tls.ECHConfigSpec, error) {
	for _, v := range msg.Value {
		if svcb.PairToKey(v) == svcb.KeyEchConfig {
			return tls.ParseECHConfigList(v.(*svcb.ECHCONFIG).ECH)
		}
	}

	return nil, fmt.Errorf("echconfig not found")
}
