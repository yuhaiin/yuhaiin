package config

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestMergeDefault(t *testing.T) {
	src := &config.Setting{
		Ipv6: false,
		Dns:  &dns.DnsConfig{},
	}

	jsondb.MergeDefault(src.ProtoReflect(), DefaultSetting("").ProtoReflect())

	data, err := protojson.MarshalOptions{Indent: "\t"}.Marshal(src)
	assert.NoError(t, err)

	t.Log(string(data))
}

func TestXxx(t *testing.T) {
	src := &config.Setting{
		Ipv6: false,
		Dns: &dns.DnsConfig{
			Resolver: map[string]*pd.Dns{
				"aaa": {},
			},
		},
	}

	cc := proto.Clone(src).(*config.Setting)

	cc.Ipv6 = true
	cc.Dns.Resolver["test"] = &pd.Dns{}

	t.Log(src.Ipv6, src.Dns.Resolver)
	t.Log(cc.Ipv6, cc.Dns.Resolver)
}
