package yuhaiin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/config"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func ifOr[T any](a bool, b, c T) T {
	if a {
		return b
	}
	return c
}

func fakeSetting(opt *Opts, path string) config.Setting {
	store := GetStore("Default").(*storeImpl)

	var listenHost string = "127.0.0.1"
	if store.GetBoolean(AllowLanKey) {
		listenHost = "0.0.0.0"
	}

	opts, _ := json.Marshal(opt)
	log.Info("fake setting config", "data", string(opts))
	settings := pc.Setting_builder{
		Ipv6:        proto.Bool(store.GetBoolean(Ipv6ProxyKey)),
		Dns:         &dns.DnsConfig{},
		SystemProxy: &pc.SystemProxy{},
		Server: listener.InboundConfig_builder{
			HijackDns: proto.Bool(store.GetBoolean(DnsHijacking)),
			// HijackDnsFakeip: opt.DNS.Fakedns,
			Sniff: listener.Sniff_builder{
				Enabled: proto.Bool(store.GetBoolean(SniffKey)),
			}.Build(),
			Inbounds: map[string]*listener.Inbound{
				"mix": listener.Inbound_builder{
					Name:    proto.String("mix"),
					Enabled: proto.Bool(store.GetInt(NewHTTPPortKey) != 0),
					Tcpudp: listener.Tcpudp_builder{
						Host:    proto.String(net.JoinHostPort(listenHost, fmt.Sprint(store.GetInt(NewHTTPPortKey)))),
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
						Driver:        listener.TunEndpointDriver(listener.TunEndpointDriver_value[store.GetString(AdvTunDriverKey)]).Enum(),
					}.Build(),
				}.Build(),
			},
		}.Build(),

		Bypass: &bypass.Config{},

		Logcat: pl.Logcat_builder{
			Level: pl.LogLevel(pl.LogLevel_value[store.GetString(LogLevel)]).Enum(),
			Save:  proto.Bool(store.GetBoolean(SaveLogcat)),
		}.Build(),
		Platform: pc.Platform_builder{
			AndroidApp: proto.Bool(true),
		}.Build(),
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
	return config.Info(), nil
}

func (w *fakeSettings) AddObserver(o func(*pc.Setting)) {
	if o != nil {
		o(w.setting)
	}
}

// android batch read only
func (w *fakeSettings) Batch(f ...func(*pc.Setting) error) error {
	config := proto.Clone(w.setting).(*pc.Setting)

	for i := range f {
		if err := f[i](config); err != nil {
			return err
		}
	}

	return nil
}

func (w *fakeSettings) Dir() string { return w.dir }

func (w *fakeSettings) updateRemoteUrl(url string) {
	w.setting.GetBypass().GetRemoteRules()[0].GetHttp().SetUrl(url)
}
