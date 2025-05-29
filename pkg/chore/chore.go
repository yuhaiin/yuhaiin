package chore

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Chore struct {
	gc.UnimplementedConfigServiceServer

	db config.DB

	onSave func(*config.Setting)

	mu sync.RWMutex
}

func NewChore(db config.DB, onSave func(*config.Setting)) gc.ConfigServiceServer {
	_ = db.Batch(func(s *config.Setting) error {
		migrate(s)
		onSave(s)
		return nil
	})

	return &Chore{db: db, onSave: onSave}
}

func migrate(s *config.Setting) {
	if s.GetBypass().GetBypassFile() != "" {
		s.GetBypass().SetRemoteRules(append(s.GetBypass().GetRemoteRules(), bypass.RemoteRule_builder{
			Enabled: proto.Bool(true),
			Name:    proto.String("old_bypass_file"),
			File: bypass.RemoteRuleFile_builder{
				Path: proto.String(s.GetBypass().GetBypassFile()),
			}.Build(),
		}.Build()))

		s.GetBypass().SetBypassFile("")
	}
}

func (c *Chore) Info(context.Context, *emptypb.Empty) (*config.Info, error) { return Info(), nil }

func (c *Chore) Load(context.Context, *emptypb.Empty) (*config.Setting, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var setting *config.Setting

	err := c.db.View(func(s *config.Setting) error {
		if !s.HasAdvancedConfig() {
			s.SetAdvancedConfig(config.AdvancedConfig_builder{
				UdpBufferSize:     proto.Int32(int32(configuration.UDPBufferSize.Load())),
				RelayBufferSize:   proto.Int32(int32(configuration.RelayBufferSize.Load())),
				UdpRingbufferSize: proto.Int32(int32(configuration.MaxUDPUnprocessedPackets.Load())),
			}.Build())
		}

		if !s.HasLogcat() {
			s.SetLogcat(log.Logcat_builder{
				Save:               proto.Bool(false),
				Level:              log.LogLevel_info.Enum(),
				IgnoreDnsError:     proto.Bool(configuration.IgnoreDnsErrorLog.Load()),
				IgnoreTimeoutError: proto.Bool(configuration.IgnoreTimeoutErrorLog.Load()),
			}.Build())
		}

		if !s.HasSystemProxy() {
			s.SetSystemProxy(config.SystemProxy_builder{
				Http:   proto.Bool(false),
				Socks5: proto.Bool(false),
			}.Build())
		}

		setting = config.Setting_builder{
			AdvancedConfig:             s.GetAdvancedConfig(),
			UseDefaultInterface:        proto.Bool(s.GetUseDefaultInterface()),
			NetInterface:               proto.String(s.GetNetInterface()),
			Ipv6:                       proto.Bool(s.GetIpv6()),
			Ipv6LocalAddrPreferUnicast: proto.Bool(s.GetIpv6LocalAddrPreferUnicast()),
			Logcat:                     s.GetLogcat(),
			SystemProxy:                s.GetSystemProxy(),
			Platform:                   s.GetPlatform(),
		}.Build()

		return nil
	})

	return setting, err

}

func (c *Chore) Save(ctx context.Context, s *config.Setting) (*emptypb.Empty, error) {
	err := c.db.Batch(func(ss *config.Setting) error {
		ss.SetIpv6(s.GetIpv6())

		ss.SetUseDefaultInterface(s.GetUseDefaultInterface())
		ss.SetNetInterface(s.GetNetInterface())
		ss.SetIpv6LocalAddrPreferUnicast(s.GetIpv6LocalAddrPreferUnicast())

		ss.SetSystemProxy(s.GetSystemProxy())

		ss.SetLogcat(s.GetLogcat())

		ss.SetAdvancedConfig(s.GetAdvancedConfig())

		c.onSave(proto.CloneOf(ss))
		return nil
	})

	return &emptypb.Empty{}, err
}

func Info() *config.Info {
	var build []string
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, v := range info.Settings {
			build = append(build, fmt.Sprintf("%s=%s", v.Key, v.Value))
		}
	}

	return (&config.Info_builder{
		Version:   proto.String(version.Version),
		Commit:    proto.String(version.GitCommit),
		BuildTime: proto.String(version.BuildTime),
		GoVersion: proto.String(runtime.Version()),
		Platform:  proto.String(runtime.GOOS + "/" + runtime.GOARCH),
		Compiler:  proto.String(runtime.Compiler),
		Arch:      proto.String(runtime.GOARCH),
		Os:        proto.String(runtime.GOOS),
		Build_:    build,
	}).Build()
}
