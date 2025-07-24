package config

import (
	"fmt"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
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

func TestUla(t *testing.T) {
	for range 10 {
		fmt.Println("-------")
		t.Log(FakeipV6UlaGenerate())
		t.Log(TunV6UlaGenerate())

		t.Log(FakeipV4UlaGenerate())
		t.Log(TunV4UlaGenerate())
		addr := TunV4UlaGenerate().Masked()
		t.Log(addr)
		addr = TunV6UlaGenerate().Masked()
		t.Log(addr)
	}
}
