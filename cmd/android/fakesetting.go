package yuhaiin

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	iconfig "github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/grpc/config"
	"google.golang.org/protobuf/types/known/emptypb"
)

func fakeSetting(opt *Opts, path string) *fakeSettings {
	opts, _ := json.Marshal(opt)
	log.Infoln("fake setting:", string(opts))
	settings := &protoconfig.Setting{
		Ipv6: opt.IPv6,
		Dns: &protoconfig.DnsSetting{
			Server:         opt.DNS.Server,
			Fakedns:        opt.DNS.Fakedns,
			FakednsIpRange: opt.DNS.FakednsIpRange,
			Remote: &protoconfig.Dns{
				Host:          opt.DNS.Remote.Host,
				Type:          protoconfig.DnsDnsType(opt.DNS.Remote.Type),
				Proxy:         opt.DNS.Remote.Proxy,
				Subnet:        opt.DNS.Remote.Subnet,
				TlsServername: opt.DNS.Remote.TlsServername,
			},
			Local: &protoconfig.Dns{
				Host:          opt.DNS.Local.Host,
				Type:          protoconfig.DnsDnsType(opt.DNS.Local.Type),
				Proxy:         opt.DNS.Local.Proxy,
				Subnet:        opt.DNS.Local.Subnet,
				TlsServername: opt.DNS.Local.TlsServername,
			},
			Bootstrap: &protoconfig.Dns{
				Host:          opt.DNS.Bootstrap.Host,
				Type:          protoconfig.DnsDnsType(opt.DNS.Bootstrap.Type),
				Proxy:         opt.DNS.Bootstrap.Proxy,
				Subnet:        opt.DNS.Bootstrap.Subnet,
				TlsServername: opt.DNS.Bootstrap.TlsServername,
			},
		},
		SystemProxy: &protoconfig.SystemProxy{},
		Server: &protoconfig.Server{
			Servers: map[string]*protoconfig.ServerProtocol{
				"socks5": {
					Protocol: &protoconfig.ServerProtocol_Socks5{
						Socks5: &protoconfig.Socks5{
							Enabled: opt.Socks5 != "",
							Host:    opt.Socks5,
						},
					},
				},
				"http": {
					Protocol: &protoconfig.ServerProtocol_Http{
						Http: &protoconfig.Http{
							Enabled: opt.Http != "",
							Host:    opt.Http,
						},
					},
				},
				"tun": {
					Protocol: &protoconfig.ServerProtocol_Tun{
						Tun: &protoconfig.Tun{
							Enabled:       true,
							Name:          fmt.Sprintf("fd://%d", opt.TUN.FD),
							Mtu:           opt.TUN.MTU,
							Gateway:       opt.TUN.Gateway,
							DnsHijacking:  opt.TUN.DNSHijacking,
							SkipMulticast: true,
							Driver:        protoconfig.TunEndpointDriver(opt.TUN.Driver),
						},
					},
				},
			},
		},

		Bypass: &protoconfig.Bypass{
			Tcp:        protoconfig.BypassMode(opt.Bypass.TCP),
			Udp:        protoconfig.BypassMode(opt.Bypass.UDP),
			BypassFile: filepath.Join(filepath.Dir(path), "yuhaiin.conf"),
		},

		Logcat: &protoconfig.Logcat{
			Level: protoconfig.LogcatLogLevel(opt.Log.LogLevel),
			Save:  opt.Log.SaveLogcat,
		},
	}

	return newFakeSetting(settings)
}

type fakeSettings struct {
	config.UnimplementedConfigDaoServer
	setting *protoconfig.Setting
}

func newFakeSetting(setting *protoconfig.Setting) *fakeSettings {
	return &fakeSettings{setting: setting}
}

func (w *fakeSettings) Load(ctx context.Context, in *emptypb.Empty) (*protoconfig.Setting, error) {
	return w.setting, nil
}

func (w *fakeSettings) Save(ctx context.Context, in *protoconfig.Setting) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (w *fakeSettings) AddObserver(o iconfig.Observer) {
	if o != nil {
		o.Update(w.setting)
	}
}
