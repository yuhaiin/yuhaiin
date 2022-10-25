package yuhaiin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	iconfig "github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	config "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	protolog "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"google.golang.org/protobuf/types/known/emptypb"
)

func fakeSetting(opt *Opts, path string) iconfig.Setting {
	opts, _ := json.Marshal(opt)
	log.Infoln("fake setting:", string(opts))
	settings := &protoconfig.Setting{
		Ipv6: opt.IPv6,
		Dns: &dns.Config{
			Server:              opt.DNS.Server,
			Fakedns:             opt.DNS.Fakedns,
			FakednsIpRange:      opt.DNS.FakednsIpRange,
			ResolveRemoteDomain: opt.DNS.ResolveRemoteDomain,
			Hosts:               opt.DNS.Hosts,
			Remote: &dns.Dns{
				Host:          opt.DNS.Remote.Host,
				Type:          dns.Type(opt.DNS.Remote.Type),
				Subnet:        opt.DNS.Remote.Subnet,
				TlsServername: opt.DNS.Remote.TlsServername,
			},
			Local: &dns.Dns{
				Host:          opt.DNS.Local.Host,
				Type:          dns.Type(opt.DNS.Local.Type),
				Subnet:        opt.DNS.Local.Subnet,
				TlsServername: opt.DNS.Local.TlsServername,
			},
			Bootstrap: &dns.Dns{
				Host:          opt.DNS.Bootstrap.Host,
				Type:          dns.Type(opt.DNS.Bootstrap.Type),
				Subnet:        opt.DNS.Bootstrap.Subnet,
				TlsServername: opt.DNS.Bootstrap.TlsServername,
			},
		},
		SystemProxy: &protoconfig.SystemProxy{},
		Server: &listener.Config{
			Servers: map[string]*listener.Protocol{
				"socks5": {
					Name:    "socks5",
					Enabled: opt.Socks5 != "",
					Protocol: &listener.Protocol_Socks5{
						Socks5: &listener.Socks5{
							Host: opt.Socks5,
						},
					},
				},
				"http": {
					Name:    "http",
					Enabled: opt.Http != "",
					Protocol: &listener.Protocol_Http{
						Http: &listener.Http{
							Host: opt.Http,
						},
					},
				},
				"tun": {
					Name:    "tun",
					Enabled: true,
					Protocol: &listener.Protocol_Tun{
						Tun: &listener.Tun{
							Name:          fmt.Sprintf("fd://%d", opt.TUN.FD),
							Mtu:           opt.TUN.MTU,
							Gateway:       opt.TUN.Gateway,
							DnsHijacking:  opt.TUN.DNSHijacking,
							SkipMulticast: true,
							Driver:        listener.TunEndpointDriver(opt.TUN.Driver),
						},
					},
				},
			},
		},

		Bypass: &bypass.Config{
			Tcp:        bypass.Mode(opt.Bypass.TCP),
			Udp:        bypass.Mode(opt.Bypass.UDP),
			BypassFile: filepath.Join(filepath.Dir(path), "yuhaiin.conf"),
			CustomRule: make(map[string]bypass.Mode),
		},

		Logcat: &protolog.Logcat{
			Level: protolog.LogLevel(opt.Log.LogLevel),
			Save:  opt.Log.SaveLogcat,
		},
	}

	applyRule(settings, opt.Bypass.Proxy, bypass.Mode_proxy)
	applyRule(settings, opt.Bypass.Block, bypass.Mode_block)
	applyRule(settings, opt.Bypass.Direct, bypass.Mode_direct)
	return newFakeSetting(settings)
}

func applyRule(settings *protoconfig.Setting, ruls string, mode bypass.Mode) {
	r := bufio.NewReader(strings.NewReader(ruls))
	for {
		line, _, err := r.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			continue
		}

		settings.Bypass.CustomRule[string(line)] = mode
	}
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
