package route

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestNested(t *testing.T) {
	data, err := protojson.Marshal(bypass.Config_builder{
		Lists: map[string]*bypass.List{
			"test": bypass.List_builder{
				Local: bypass.ListLocal_builder{
					Lists: []string{"test"},
				}.Build(),
				ErrorMsgs: []string{"test", "test2"},
			}.Build(),
		},
	}.Build())
	assert.NoError(t, err)
	t.Log(string(data))

	t.Run("sort", func(t *testing.T) {
		rules := []*bypass.Rule{
			bypass.Rule_builder{
				Host: bypass.Host_builder{}.Build(),
			}.Build(),
			bypass.Rule_builder{
				Process: bypass.Process_builder{}.Build(),
			}.Build(),
			bypass.Rule_builder{
				Inbound: bypass.Inbound_builder{}.Build(),
			}.Build(),
			bypass.Rule_builder{
				Process: bypass.Process_builder{}.Build(),
			}.Build(),
		}

		t.Log(sortRule(rules))
	})
}
