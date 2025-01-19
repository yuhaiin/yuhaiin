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
	settings := pc.Setting_builder{
		Ipv6: proto.Bool(store.GetBoolean(Ipv6ProxyKey)),
		Dns: dns.DnsConfig_builder{
			Server:           proto.String(ifOr(store.GetInt(AdvDnsPortKey) == 0, "", net.JoinHostPort(listenHost, fmt.Sprint(store.GetInt(AdvDnsPortKey))))),
			Fakedns:          proto.Bool(store.GetString(AdvFakeDnsCidrKey) != "" || store.GetString(AdvFakeDnsv6CidrKey) != ""),
			FakednsIpRange:   proto.String(store.GetString(AdvFakeDnsCidrKey)),
			FakednsIpv6Range: proto.String(store.GetString(AdvFakeDnsv6CidrKey)),
			Hosts:            store.GetStringMap(NewHostsKey),

			Resolver: map[string]*dns.Dns{
				"direct": dns.Dns_builder{
					Host:          proto.String(store.GetString(LocalDnsHostKey)),
					Type:          dns.Type(dns.Type_value[store.GetString(LocalDnsTypeKey)]).Enum(),
					Subnet:        proto.String(store.GetString(LocalDnsSubnetKey)),
					TlsServername: proto.String(store.GetString(LocalDnsTlsServerNameKey)),
				}.Build(),
				"proxy": dns.Dns_builder{
					Host:          proto.String(store.GetString(RemoteDnsHostKey)),
					Type:          dns.Type(dns.Type_value[store.GetString(RemoteDnsTypeKey)]).Enum(),
					Subnet:        proto.String(store.GetString(RemoteDnsSubnetKey)),
					TlsServername: proto.String(store.GetString(RemoteDnsTlsServerNameKey)),
				}.Build(),
				"bootstrap": dns.Dns_builder{
					Host:          proto.String(store.GetString(BootstrapDnsHostKey)),
					Type:          dns.Type(dns.Type_value[store.GetString(BootstrapDnsTypeKey)]).Enum(),
					Subnet:        proto.String(store.GetString(BootstrapDnsSubnetKey)),
					TlsServername: proto.String(store.GetString(BootstrapDnsTlsServerNameKey)),
				}.Build(),
			},
		}.Build(),
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
			settings.GetBypass().SetCustomRuleV3(append(settings.GetBypass().GetCustomRuleV3(), zz))
		}

		zz.SetHostname(append(zz.GetHostname(), z[0]))
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
	w.setting.GetBypass().GetRemoteRules()[0].GetHttp().SetUrl(url)
}
