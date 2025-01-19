package appapi

import (
	"fmt"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"google.golang.org/protobuf/proto"
)

func TestMarshalSize(t *testing.T) {
	s := config.Setting_builder{
		Ipv6: proto.Bool(true),
		SystemProxy: config.SystemProxy_builder{
			Http: proto.Bool(true),
		}.Build(),
		Bypass: bypass.Config_builder{
			CustomRuleV3: []*bypass.ModeConfig{
				bypass.ModeConfig_builder{
					Hostname: []string{"www.google.com"},
				}.Build(),
			},
		}.Build(),
	}.Build()

	marshal := proto.MarshalOptions{}
	size := marshal.Size(s)

	buf := pool.GetBytes(size)
	defer pool.PutBytes(buf)

	data, err := marshal.MarshalAppend(buf[:0], s)
	assert.NoError(t, err)

	fmt.Printf("%p %p\n", buf, data)

	t.Log(size, len(data), data)
}
