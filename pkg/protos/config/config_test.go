package config

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestMergeDefault(t *testing.T) {
	src := Setting_builder{
		Ipv6: proto.Bool(false),
		Dns:  &dns.DnsConfig{},
	}.Build()

	jsondb.MergeDefault(src.ProtoReflect(), DefaultSetting("").ProtoReflect())

	data, err := protojson.MarshalOptions{Indent: "\t"}.Marshal(src)
	assert.NoError(t, err)

	t.Log(string(data))
}

func TestXxx(t *testing.T) {
	src := Setting_builder{
		Ipv6: proto.Bool(false),
		Dns: dns.DnsConfig_builder{
			Resolver: map[string]*pd.Dns{
				"aaa": {},
			},
		}.Build(),
	}.Build()

	cc := proto.CloneOf(src)

	cc.SetIpv6(true)
	cc.GetDns().GetResolver()["test"] = &pd.Dns{}

	t.Log(src.GetIpv6(), src.GetDns().GetResolver())
	t.Log(cc.GetIpv6(), cc.GetDns().GetResolver())
}
