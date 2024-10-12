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
	var listenHost string = "127.0.0.1"
	if opt.MapStore.GetBoolean(AllowLanKey) {
		listenHost = "0.0.0.0"
	}

	opts, _ := json.Marshal(opt)
	log.Info("fake setting config", "data", string(opts))
	settings := &pc.Setting{
		Ipv6: opt.MapStore.GetBoolean(IPv6Key),
		Dns: &dns.DnsConfig{
			Server:           ifOr(opt.MapStore.GetInt(DNSPortKey) == 0, "", net.JoinHostPort(listenHost, fmt.Sprint(opt.MapStore.GetInt(DNSPortKey)))),
			Fakedns:          opt.MapStore.GetString(FakeDNSCIDRKey) != "" || opt.MapStore.GetString(FakeDNSv6CIDRKey) != "",
			FakednsIpRange:   opt.MapStore.GetString(FakeDNSCIDRKey),
			FakednsIpv6Range: opt.MapStore.GetString(FakeDNSv6CIDRKey),
			Hosts:            make(map[string]string),
			Remote: &dns.Dns{
				Host:          opt.MapStore.GetString(RemoteDNSHostKey),
				Type:          dns.Type(dns.Type_value[opt.MapStore.GetString(RemoteDNSTypeKey)]),
				Subnet:        opt.MapStore.GetString(RemoteDNSSubnetKey),
				TlsServername: opt.MapStore.GetString(RemoteDNSTLSServerNameKey),
			},
			Local: &dns.Dns{
				Host:          opt.MapStore.GetString(LocalDNSHostKey),
				Type:          dns.Type(dns.Type_value[opt.MapStore.GetString(LocalDNSTypeKey)]),
				Subnet:        opt.MapStore.GetString(LocalDNSSubnetKey),
				TlsServername: opt.MapStore.GetString(LocalDNSTLSServerNameKey),
			},
			Bootstrap: &dns.Dns{
				Host:          opt.MapStore.GetString(BootstrapDNSHostKey),
				Type:          dns.Type(dns.Type_value[opt.MapStore.GetString(BootstrapDNSTypeKey)]),
				Subnet:        opt.MapStore.GetString(BootstrapDNSSubnetKey),
				TlsServername: opt.MapStore.GetString(BootstrapDNSTLSServerNameKey),
			},
		},
		SystemProxy: &pc.SystemProxy{},
		Server: &listener.InboundConfig{
			HijackDns: opt.MapStore.GetBoolean(DNSHijackingKey),
			// HijackDnsFakeip: opt.DNS.Fakedns,
			Sniff: &listener.Sniff{
				Enabled: opt.MapStore.GetBoolean(SniffKey),
			},
			Inbounds: map[string]*listener.Inbound{
				"mix": {
					Name:    "mix",
					Enabled: opt.MapStore.GetInt(HTTPPortKey) != 0,
					Network: &listener.Inbound_Tcpudp{
						Tcpudp: &listener.Tcpudp{
							Host:    net.JoinHostPort(listenHost, fmt.Sprint(opt.MapStore.GetInt(HTTPPortKey))),
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
							Driver:        listener.TunEndpointDriver(listener.TunEndpointDriver_value[opt.MapStore.GetString(TunDriverKey)]),
						},
					},
				},
			},
		},

		Bypass: &bypass.Config{
			Tcp:            bypass.Mode(bypass.Mode_value[opt.MapStore.GetString(TCPBypassKey)]),
			Udp:            bypass.Mode(bypass.Mode_value[opt.MapStore.GetString(UDPBypassKey)]),
			CustomRuleV3:   []*bypass.ModeConfig{},
			ResolveLocally: opt.MapStore.GetBoolean(RemoteDNSResolveDomainKey),
			RemoteRules: []*bypass.RemoteRule{
				{
					Enabled: true,
					Name:    "remote",
					Object: &bypass.RemoteRule_Http{
						Http: &bypass.RemoteRuleHttp{
							Url: opt.MapStore.GetString(RuleByPassUrlKey),
						},
					},
				},
			},
		},

		Logcat: &pl.Logcat{
			Level: pl.LogLevel(pl.LogLevel_value[opt.MapStore.GetString(LogLevelKey)]),
			Save:  opt.MapStore.GetBoolean(SaveLogcatKey),
		},
		Platform: &pc.Platform{
			AndroidApp: true,
		},
	}

	if err := json.Unmarshal([]byte(opt.MapStore.GetString(HostsKey)), &settings.Dns.Hosts); err != nil {
		log.Warn("unmarshal hosts failed", "err", err)
	}

	if opt.MapStore.GetBoolean(UDPProxyFQDNKey) {
		settings.Bypass.UdpProxyFqdn = bypass.UdpProxyFqdnStrategy_skip_resolve
	}

	applyRule(settings, opt.MapStore.GetString(ProxyKey), bypass.Mode_proxy)
	applyRule(settings, opt.MapStore.GetString(BlockKey), bypass.Mode_block)
	applyRule(settings, opt.MapStore.GetString(DirectKey), bypass.Mode_direct)
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
