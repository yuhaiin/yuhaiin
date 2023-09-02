package config

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestCheckDNS(t *testing.T) {
	z := &dns.Dns{
		Host: "example.com",
	}

	t.Log(CheckBootstrapDns(z))

	z.Host = "1.1.1.1"
	t.Log(CheckBootstrapDns(z))

	z.Host = "1.1.1.1:53"
	t.Log(CheckBootstrapDns(z))

	z.Host = "ff::ff"
	t.Log(CheckBootstrapDns(z))

	z.Host = "[ff::ff]:53"
	t.Log(CheckBootstrapDns(z))

	z.Host = "1.1.1.1/dns-query"
	t.Log(CheckBootstrapDns(z))
}

func TestMergeDefault(t *testing.T) {
	src := &config.Setting{
		Ipv6: false,
		Dns: &dns.Config{
			Remote: &dns.Dns{
				Host:          "xxxx",
				Type:          dns.Type_udp,
				Subnet:        "",
				TlsServername: "",
			},
		},
	}

	jsondb.MergeDefault(src.ProtoReflect(), defaultSetting("").ProtoReflect())

	data, err := protojson.MarshalOptions{Indent: "\t"}.Marshal(src)
	assert.NoError(t, err)

	t.Log(string(data))
}
