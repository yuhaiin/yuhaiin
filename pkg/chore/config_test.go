package chore

import (
	"encoding/json/v2"
	"fmt"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/schema/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
)

func TestMergeDefault(t *testing.T) {
	src := config.Setting_builder{
		Ipv6: new(false),
		Dns:  &config.DnsConfig{},
	}.Build()

	jsondb.MergeDefault(src, config.DefaultSetting(""))

	data, err := json.Marshal(src)
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
