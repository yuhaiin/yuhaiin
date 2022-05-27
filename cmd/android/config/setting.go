package config

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/types/known/emptypb"
)

var _ config.ConfigDaoServer = (*WrapSetting)(nil)

type WrapSetting struct {
	config.UnimplementedConfigDaoServer
	setting *config.Setting
	config  config.ConfigDaoServer
}

func NewWrapSetting(config config.ConfigDaoServer, setting *config.Setting) *WrapSetting {
	return &WrapSetting{config: config, setting: setting}
}

func (w *WrapSetting) Load(ctx context.Context, in *emptypb.Empty) (*config.Setting, error) {
	return w.config.Load(ctx, in)
}
func (w *WrapSetting) Save(ctx context.Context, in *config.Setting) (*emptypb.Empty, error) {
	in.Dns.Server = w.setting.Dns.Server
	in.Dns.Fakedns = w.setting.Dns.Fakedns
	in.Server = w.setting.Server
	in.Bypass = w.setting.Bypass

	return w.config.Save(ctx, in)
}
