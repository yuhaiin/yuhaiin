package macos

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/chore"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func fakeDB(opt *Opts, path string) pc.DB {
	settings := pc.Setting_builder{
		Server: listener.InboundConfig_builder{
			HijackDns: proto.Bool(true),
			// HijackDnsFakeip: opt.DNS.Fakedns,
			Sniff: listener.Sniff_builder{
				Enabled: proto.Bool(true),
			}.Build(),
			Inbounds: map[string]*listener.Inbound{
				"mix": listener.Inbound_builder{
					Name:    proto.String("mix"),
					Enabled: proto.Bool(false),
					Tcpudp: listener.Tcpudp_builder{
						Host:    proto.String("127.0.0.1:0"),
						Control: listener.TcpUdpControl_tcp_udp_control_all.Enum(),
					}.Build(),
					Mix: &listener.Mixed{},
				}.Build(),
				"tun": listener.Inbound_builder{
					Name:    proto.String("tun"),
					Enabled: proto.Bool(true),
					Empty:   &listener.Empty{},
					Tun: listener.Tun_builder{
						Name:          proto.String(fmt.Sprintf("fd://%d", opt.TUN.FD)),
						Mtu:           proto.Int32(opt.TUN.MTU),
						Portal:        proto.String(opt.TUN.Portal),
						PortalV6:      proto.String(opt.TUN.PortalV6),
						SkipMulticast: proto.Bool(true),
						Route:         &listener.Route{},
						Driver:        listener.Tun_system_gvisor.Enum(),
					}.Build(),
				}.Build(),
			},
		}.Build(),

		Dns:         &dns.DnsConfig{},
		SystemProxy: &pc.SystemProxy{},
		Bypass:      &bypass.Config{},
		Logcat:      &pl.Logcat{},
		Platform:    pc.Platform_builder{}.Build(),
	}.Build()

	return newFakeSetting(settings, filepath.Dir(path))
}

type fakeSettings struct {
	gc.UnimplementedConfigServiceServer
	setting *pc.Setting
	dir     string
}

func newFakeSetting(setting *pc.Setting, dir string) *fakeSettings {
	return &fakeSettings{setting: setting, dir: dir}
}

func (w *fakeSettings) View(f ...func(*pc.Setting) error) error {

	for i := range f {
		if err := f[i](w.setting); err != nil {
			return err
		}
	}

	return nil
}

func (w *fakeSettings) Update(f func(*pc.Setting) error) error {
	return fmt.Errorf("android not support update settings in web ui")
}

func (w *fakeSettings) Load(ctx context.Context, in *emptypb.Empty) (*pc.Setting, error) {
	return w.setting, nil
}

func (w *fakeSettings) Save(ctx context.Context, in *pc.Setting) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, fmt.Errorf("android not support update settings in web ui")
}

func (c *fakeSettings) Info(context.Context, *emptypb.Empty) (*pc.Info, error) {
	return chore.Info(), nil
}

func (w *fakeSettings) AddObserver(o func(*pc.Setting)) {
	if o != nil {
		o(w.setting)
	}
}

// android batch read only
func (w *fakeSettings) Batch(f ...func(*pc.Setting) error) error {
	config := proto.CloneOf(w.setting)

	for i := range f {
		if err := f[i](config); err != nil {
			return err
		}
	}

	return nil
}

func (w *fakeSettings) Dir() string { return w.dir }
