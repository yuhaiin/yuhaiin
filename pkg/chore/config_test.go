package chore

import (
	"fmt"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestMergeDefault(t *testing.T) {
	src := config.Setting_builder{
		Ipv6: proto.Bool(false),
		Dns:  &config.DnsConfig{},
	}.Build()

	jsondb.MergeDefault(src.ProtoReflect(), config.DefaultSetting("").ProtoReflect())

	data, err := protojson.MarshalOptions{Indent: "\t"}.Marshal(src)
	assert.NoError(t, err)

	t.Log(string(data))
}

func TestUla(t *testing.T) {
	for range 10 {
		fmt.Println("-------")
		t.Log(config.FakeipV6UlaGenerate())
		t.Log(config.TunV6UlaGenerate())

		t.Log(config.FakeipV4UlaGenerate())
		t.Log(config.TunV4UlaGenerate())
		addr := config.TunV4UlaGenerate().Masked()
		t.Log(addr)
		addr = config.TunV6UlaGenerate().Masked()
		t.Log(addr)
	}
}
