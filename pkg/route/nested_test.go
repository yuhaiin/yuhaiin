package route

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestNested(t *testing.T) {
	data, err := protojson.Marshal(config.BypassConfig_builder{
		Lists: map[string]*config.List{
			"test": config.List_builder{
				Local: config.ListLocal_builder{
					Lists: []string{"test"},
				}.Build(),
				ErrorMsgs: []string{"test", "test2"},
			}.Build(),
		},
	}.Build())
	assert.NoError(t, err)
	t.Log(string(data))

	t.Run("sort", func(t *testing.T) {
		rules := []*config.Rule{
			config.Rule_builder{
				Host: config.Host_builder{}.Build(),
			}.Build(),
			config.Rule_builder{
				Process: config.Process_builder{}.Build(),
			}.Build(),
			config.Rule_builder{
				Inbound: config.Source_builder{}.Build(),
			}.Build(),
			config.Rule_builder{
				Process: config.Process_builder{}.Build(),
			}.Build(),
		}

		t.Log(sortRule(rules))
	})
}
