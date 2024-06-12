package yuhaiin

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/components/config"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"github.com/go-json-experiment/json"
	"google.golang.org/protobuf/types/known/emptypb"
)

func fakeSetting(opt *Opts, path string) config.Setting {
	opts, _ := json.Marshal(opt)
	log.Info("fake setting config", "data", string(opts))
	settings := &pc.Setting{
		Ipv6: opt.IPv6,
		Dns: &dns.DnsConfig{
			Server:              opt.DNS.Server,
			Fakedns:             opt.DNS.Fakedns,
			FakednsIpRange:      opt.DNS.FakednsIpRange,
			FakednsIpv6Range:    opt.DNS.FakednsIpv6Range,
			ResolveRemoteDomain: opt.DNS.ResolveRemoteDomain,
			Hosts:               make(map[string]string),
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
		SystemProxy: &pc.SystemProxy{},
		Server: &listener.InboundConfig{
			HijackDns:       opt.TUN.DNSHijacking,
			HijackDnsFakeip: opt.DNS.Fakedns,
			Inbounds: map[string]*listener.Inbound{
				"mix": {
					Name:    "mix",
					Enabled: opt.Http != "",
					Network: &listener.Inbound_Tcpudp{
						Tcpudp: &listener.Tcpudp{
							Host:    opt.Http,
							Control: listener.TcpUdpControl_tcp_udp_control_all,
						},
					},
					Protocol: &listener.Inbound_Mix{
						Mix: &listener.Mixed{},
					},
				},
				"tun": {
					Name:    "tun",
					Enabled: true,
					Network: &listener.Inbound_Empty{Empty: &listener.Empty{}},
					Protocol: &listener.Inbound_Tun{
						Tun: &listener.Tun{
							Name:          fmt.Sprintf("fd://%d", opt.TUN.FD),
							Mtu:           opt.TUN.MTU,
							Portal:        opt.TUN.Portal,
							PortalV6:      opt.TUN.PortalV6,
							SkipMulticast: true,
							Route:         &listener.Route{},
							Driver:        listener.TunEndpointDriver(opt.TUN.Driver),
						},
					},
				},
			},
		},

		Bypass: &bypass.BypassConfig{
			Tcp:          bypass.Mode(opt.Bypass.TCP),
			Udp:          bypass.Mode(opt.Bypass.UDP),
			Sniffy:       opt.Bypass.Sniffy,
			BypassFile:   filepath.Join(filepath.Dir(path), "yuhaiin.conf"),
			CustomRuleV3: []*bypass.ModeConfig{},
		},

		Logcat: &pl.Logcat{
			Level: pl.LogLevel(opt.Log.LogLevel),
			Save:  opt.Log.SaveLogcat,
		},
	}

	if err := json.Unmarshal(opt.DNS.Hosts, &settings.Dns.Hosts); err != nil {
		log.Warn("unmarshal hosts failed", "err", err)
	}

	if opt.Bypass.UDPSkipResolveFqdn {
		settings.Bypass.UdpProxyFqdn = bypass.UdpProxyFqdnStrategy_skip_resolve
	}

	applyRule(settings, opt.Bypass.Proxy, bypass.Mode_proxy)
	applyRule(settings, opt.Bypass.Block, bypass.Mode_block)
	applyRule(settings, opt.Bypass.Direct, bypass.Mode_direct)
	return newFakeSetting(settings)
}

func applyRule(settings *pc.Setting, ruls string, mode bypass.Mode) {
	cache := map[string]*bypass.ModeConfig{}

	r := bufio.NewScanner(strings.NewReader(ruls))
	for r.Scan() {
		line := r.Bytes()

		z := bytes.FieldsFunc(line, func(r rune) bool { return r == ',' })
		if len(z) == 0 {
			continue
		}

		xx := &bypass.ModeConfig{Mode: mode}

		xx.StoreKV(z[1:])

		var key string
		if xx.GetMode() == bypass.Mode_proxy {
			key = xx.GetMode().String() + xx.GetTag()
		} else {
			key = xx.GetMode().String()
		}

		zz, ok := cache[key]
		if ok {
			xx = zz
		} else {
			cache[key] = xx
			settings.Bypass.CustomRuleV3 = append(settings.Bypass.CustomRuleV3, xx)
		}

		xx.Hostname = append(xx.Hostname, string(z[0]))
	}
}

type fakeSettings struct {
	gc.UnimplementedConfigServiceServer
	setting *pc.Setting
}

func newFakeSetting(setting *pc.Setting) *fakeSettings {
	return &fakeSettings{setting: setting}
}

func (w *fakeSettings) Load(ctx context.Context, in *emptypb.Empty) (*pc.Setting, error) {
	return w.setting, nil
}
func (w *fakeSettings) Save(ctx context.Context, in *pc.Setting) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
func (c *fakeSettings) Info(context.Context, *emptypb.Empty) (*pc.Info, error) {
	return config.Info(), nil
}

func (w *fakeSettings) AddObserver(o config.Observer) {
	if o != nil {
		o.Update(w.setting)
	}
}
