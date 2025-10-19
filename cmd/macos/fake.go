package macos

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/chore"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func fakeDB(opt *Opts, path string) chore.DB {
	settings := config.Setting_builder{
		Server: config.InboundConfig_builder{
			HijackDns: proto.Bool(true),
			// HijackDnsFakeip: opt.DNS.Fakedns,
			Sniff: config.Sniff_builder{
				Enabled: proto.Bool(true),
			}.Build(),
			Inbounds: map[string]*config.Inbound{
				"mix": config.Inbound_builder{
					Name:    proto.String("mix"),
					Enabled: proto.Bool(false),
					Tcpudp: config.Tcpudp_builder{
						Host:    proto.String("127.0.0.1:0"),
						Control: config.TcpUdpControl_tcp_udp_control_all.Enum(),
					}.Build(),
					Mix: &config.Mixed{},
				}.Build(),
				"tun": config.Inbound_builder{
					Name:    proto.String("tun"),
					Enabled: proto.Bool(true),
					Empty:   &config.Empty{},
					Tun: config.Tun_builder{
						Name:          proto.String(fmt.Sprintf("fd://%d", opt.TUN.FD)),
						Mtu:           proto.Int32(opt.TUN.MTU),
						Portal:        proto.String(opt.TUN.Portal),
						PortalV6:      proto.String(opt.TUN.PortalV6),
						SkipMulticast: proto.Bool(true),
						Route:         &config.Route{},
						Driver:        config.Tun_system_gvisor.Enum(),
					}.Build(),
				}.Build(),
			},
		}.Build(),

		Dns:         &config.DnsConfig{},
		SystemProxy: &config.SystemProxy{},
		Bypass:      &config.BypassConfig{},
		Logcat:      &config.Logcat{},
		Platform:    config.Platform_builder{}.Build(),
	}.Build()

	return newFakeSetting(settings, filepath.Dir(path))
}

type fakeSettings struct {
	api.UnimplementedConfigServiceServer
	setting *config.Setting
	dir     string
}

func newFakeSetting(setting *config.Setting, dir string) *fakeSettings {
	return &fakeSettings{setting: setting, dir: dir}
}

func (w *fakeSettings) View(f ...func(*config.Setting) error) error {

	for i := range f {
		if err := f[i](w.setting); err != nil {
			return err
		}
	}

	return nil
}

func (w *fakeSettings) Update(f func(*config.Setting) error) error {
	return fmt.Errorf("android not support update settings in web ui")
}

func (w *fakeSettings) Load(ctx context.Context, in *emptypb.Empty) (*config.Setting, error) {
	return w.setting, nil
}

func (w *fakeSettings) Save(ctx context.Context, in *config.Setting) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, fmt.Errorf("android not support update settings in web ui")
}

func (c *fakeSettings) Info(context.Context, *emptypb.Empty) (*config.Info, error) {
	return chore.Info(), nil
}

func (w *fakeSettings) AddObserver(o func(*config.Setting)) {
	if o != nil {
		o(w.setting)
	}
}

// android batch read only
func (w *fakeSettings) Batch(f ...func(*config.Setting) error) error {
	config := proto.CloneOf(w.setting)

	for i := range f {
		if err := f[i](config); err != nil {
			return err
		}
	}

	return nil
}

func (w *fakeSettings) Dir() string { return w.dir }
