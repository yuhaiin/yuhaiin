package config

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestMergeDefault(t *testing.T) {
	src := &config.Setting{
		Ipv6: false,
		Dns: &dns.DnsConfig{
			Remote: &dns.Dns{
				Host:          "xxxx",
				Type:          dns.Type_udp,
				Subnet:        "",
				TlsServername: "",
			},
		},
	}

	jsondb.MergeDefault(src.ProtoReflect(), DefaultSetting("").ProtoReflect())

	data, err := protojson.MarshalOptions{Indent: "\t"}.Marshal(src)
	assert.NoError(t, err)

	t.Log(string(data))
}
