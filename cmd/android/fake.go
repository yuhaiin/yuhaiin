package yuhaiin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/config"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"github.com/Asutorufa/yuhaiin/pkg/route"
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
	settings := &pc.Setting{
		Ipv6: store.GetBoolean(Ipv6ProxyKey),
		Dns: &dns.DnsConfig{
			Server:           ifOr(store.GetInt(AdvDnsPortKey) == 0, "", net.JoinHostPort(listenHost, fmt.Sprint(store.GetInt(AdvDnsPortKey)))),
			Fakedns:          store.GetString(AdvFakeDnsCidrKey) != "" || store.GetString(AdvFakeDnsv6CidrKey) != "",
			FakednsIpRange:   store.GetString(AdvFakeDnsCidrKey),
			FakednsIpv6Range: store.GetString(AdvFakeDnsv6CidrKey),
			Hosts:            store.GetStringMap(NewHostsKey),
			Remote: &dns.Dns{
				Host:          store.GetString(RemoteDnsHostKey),
				Type:          dns.Type(dns.Type_value[store.GetString(RemoteDnsTypeKey)]),
				Subnet:        store.GetString(RemoteDnsSubnetKey),
				TlsServername: store.GetString(RemoteDnsTlsServerNameKey),
			},
			Local: &dns.Dns{
				Host:          store.GetString(LocalDnsHostKey),
				Type:          dns.Type(dns.Type_value[store.GetString(LocalDnsTypeKey)]),
				Subnet:        store.GetString(LocalDnsSubnetKey),
				TlsServername: store.GetString(LocalDnsTlsServerNameKey),
			},
			Bootstrap: &dns.Dns{
				Host:          store.GetString(BootstrapDnsHostKey),
				Type:          dns.Type(dns.Type_value[store.GetString(BootstrapDnsTypeKey)]),
				Subnet:        store.GetString(BootstrapDnsSubnetKey),
				TlsServername: store.GetString(BootstrapDnsTlsServerNameKey),
			},
		},
		SystemProxy: &pc.SystemProxy{},
		Server: &listener.InboundConfig{
			HijackDns: store.GetBoolean(DnsHijacking),
			// HijackDnsFakeip: opt.DNS.Fakedns,
			Sniff: &listener.Sniff{
				Enabled: store.GetBoolean(Sniff),
			},
			Inbounds: map[string]*listener.Inbound{
				"mix": {
					Name:    "mix",
					Enabled: store.GetInt(NewHTTPPortKey) != 0,
					Network: &listener.Inbound_Tcpudp{
						Tcpudp: &listener.Tcpudp{
							Host:    net.JoinHostPort(listenHost, fmt.Sprint(store.GetInt(NewHTTPPortKey))),
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
							Driver:        listener.TunEndpointDriver(listener.TunEndpointDriver_value[store.GetString(AdvTunDriverKey)]),
						},
					},
				},
			},
		},

		Bypass: &bypass.Config{
			Tcp:            bypass.Mode(bypass.Mode_value[store.GetString(BypassTcp)]),
			Udp:            bypass.Mode(bypass.Mode_value[store.GetString(BypassUdp)]),
			CustomRuleV3:   []*bypass.ModeConfig{},
			ResolveLocally: store.GetBoolean(RemoteDnsResolveDomainKey),
			UdpProxyFqdn:   ifOr(store.GetBoolean(UdpProxyFqdn), bypass.UdpProxyFqdnStrategy_skip_resolve, bypass.UdpProxyFqdnStrategy_udp_proxy_fqdn_strategy_default),
			RemoteRules: []*bypass.RemoteRule{
				{
					Enabled: true,
					Name:    "remote",
					Object: &bypass.RemoteRule_Http{
						Http: &bypass.RemoteRuleHttp{
							Url: store.GetString(RuleUpdateBypassFile),
						},
					},
				},
			},
		},

		Logcat: &pl.Logcat{
			Level: pl.LogLevel(pl.LogLevel_value[store.GetString(LogLevel)]),
			Save:  store.GetBoolean(SaveLogcat),
		},
		Platform: &pc.Platform{
			AndroidApp: true,
		},
	}

	applyRule(settings, store.GetString(RuleProxy), bypass.Mode_proxy)
	applyRule(settings, store.GetString(RuleBlock), bypass.Mode_block)
	applyRule(settings, store.GetString(RuleDirect), bypass.Mode_direct)
	return newFakeSetting(settings, filepath.Dir(path))
}

func applyRule(settings *pc.Setting, ruls string, mode bypass.Mode) {
	cache := map[route.Args]*bypass.ModeConfig{}

	r := bufio.NewScanner(strings.NewReader(ruls))
	for r.Scan() {
		line := r.Text()

		z := strings.FieldsFunc(line, func(r rune) bool { return r == ',' })
		if len(z) == 0 {
			continue
		}

		xx := route.ParseArgs(mode, z[1:])

		zz, ok := cache[xx]
		if !ok {
			zz = xx.ToModeConfig(nil)
			cache[xx] = zz
			settings.Bypass.CustomRuleV3 = append(settings.Bypass.CustomRuleV3, zz)
		}

		zz.Hostname = append(zz.Hostname, z[0])
	}
}

type fakeSettings struct {
	gc.UnimplementedConfigServiceServer
	setting *pc.Setting
	dir     string
}

func newFakeSetting(setting *pc.Setting, dir string) *fakeSettings {
	return &fakeSettings{setting: setting, dir: dir}
}

func (w *fakeSettings) View(f func(*pc.Setting) error) error {
	return f(w.setting)
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

func (w *fakeSettings) AddObserver(o config.Observer) {
	if o != nil {
		o.Update(w.setting)
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
	w.setting.Bypass.RemoteRules[0].GetHttp().Url = url
}
