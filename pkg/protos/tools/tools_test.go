package tools

import (
	"context"
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/config"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type mockSetting struct {
	config.Setting
	ss *pc.Setting
}

func (m *mockSetting) Load(context.Context, *emptypb.Empty) (*pc.Setting, error) { return m.ss, nil }
func (m *mockSetting) Save(context.Context, *pc.Setting) (*emptypb.Empty, error) {
	return nil, os.ErrInvalid
}
func (m *mockSetting) Info(context.Context, *emptypb.Empty) (*pc.Info, error) {
	return nil, os.ErrInvalid
}
func (m *mockSetting) AddObserver(config.Observer) {}

func TestSaveRemoteRule(t *testing.T) {
	var rule = `
https://raw.githubusercontent.com/yuhaiin/kitte/main/yuhaiin/accelerated-domains.china.conf DIRECT,tag=CN
https://raw.githubusercontent.com/yuhaiin/kitte/main/yuhaiin/apple.china.conf DIRECT,tag=APPLE-CN
https://raw.githubusercontent.com/yuhaiin/kitte/main/yuhaiin/google.china.conf DIRECT,tag=GOOGLE-CN
https://raw.githubusercontent.com/yuhaiin/kitte/main/common/lan.acl DIRECT,tag=LAN
https://raw.githubusercontent.com/yuhaiin/kitte/main/geoip/geoip/CN.conf DIRECT,tag=CN
https://raw.githubusercontent.com/yuhaiin/kitte/main/yuhaiin/abroad.conf PROXY
https://raw.githubusercontent.com/yuhaiin/kitte/main/yuhaiin/abroad_ip.conf PROXY
file://sub-rule.txt
https://raw.githubusercontent.com/yuhaiin/kitte/main/yuhaiin/bt.conf`

	var subRule = `
www.google.com DIRECT,tag=CN
`

	err := os.MkdirAll("tmp", 0755)
	assert.NoError(t, err)
	err = os.WriteFile("tmp/raw-rule.txt", []byte(rule), 0644)
	assert.NoError(t, err)
	err = os.WriteFile("tmp/sub-rule.txt", []byte(subRule), 0644)
	assert.NoError(t, err)

	tt := NewTools(direct.Default, &mockSetting{ss: &pc.Setting{
		Bypass: &bypass.BypassConfig{
			BypassFile: "tmp/rule.txt",
		},
	}}, nil)

	t.Log(tt.SaveRemoteBypassFile(context.TODO(), &wrapperspb.StringValue{
		Value: "file://raw-rule.txt",
	}))
}
