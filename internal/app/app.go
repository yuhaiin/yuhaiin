package app

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/appapi"
	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/route"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	ybbolt "github.com/Asutorufa/yuhaiin/pkg/utils/cache/bbolt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.etcd.io/bbolt"
	bolterr "go.etcd.io/bbolt/errors"

	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/drop"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/grpc"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mux"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/reality"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/reverse"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks4a"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/trojan"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vless"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
)

func AddComponent[T any](a *appapi.Start, name string, t T) T {
	if z, ok := any(t).(io.Closer); ok {
		a.AddCloser(name, z)
	}

	return t
}

func OpenBboltDB(path string) (*bbolt.DB, error) {
	db, err := bbolt.Open(path, os.ModePerm, &bbolt.Options{Timeout: time.Second * 2})
	switch err {
	case bolterr.ErrInvalid, bolterr.ErrChecksum, bolterr.ErrVersionMismatch:
		if err = os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove invalid cache file failed: %w", err)
		}
		log.Info("remove invalid cache file and create new one")
		return bbolt.Open(path, os.ModePerm, &bbolt.Options{Timeout: time.Second})
	}

	return db, err
}

func Start(opt appapi.Start) (_ *appapi.Components, err error) {
	so := &opt

	configuration.DataDir.Store(so.ConfigPath)

	db, err := OpenBboltDB(PathGenerator.Cache(so.ConfigPath))
	if err != nil {
		return nil, fmt.Errorf("init bbolt cache failed: %w", err)
	}
	so.AddCloser("bbolt_db", db)
	configuration.BBoltDB = db

	httpListener, err := net.Listen("tcp", so.Host)
	if err != nil {
		return nil, err
	}
	so.AddCloser("http_listener", httpListener)

	so.Setting.AddObserver(func(s *pc.Setting) {
		log.Set(s.GetLogcat(), PathGenerator.Log(so.ConfigPath))
	})

	fmt.Println(version.Art)
	log.Info("config", "path", so.ConfigPath, "grpc&http host", so.Host)

	so.Setting.AddObserver(sysproxy.Update())
	so.Setting.AddObserver(func(s *pc.Setting) {
		iface := atomicx.NewValue("")

		dialer.DefaultInterfaceName = func() string {
			if !s.GetUseDefaultInterface() {
				return s.GetNetInterface()
			}

			x := iface.Load()
			if x != "" {
				if _, err := net.InterfaceByName(x); err == nil {
					return x
				}
			}

			ifacestr, err := interfaces.DefaultRouteInterface()
			if err != nil {
				log.Error("get default interface failed", "error", err)
			} else {
				log.Info("use default interface", "interface", ifacestr)
				iface.Store(ifacestr)
			}

			return ifacestr
		}
	})
	so.Setting.AddObserver(func(s *pc.Setting) { dialer.DefaultIPv6PreferUnicastLocalAddr = s.GetIpv6LocalAddrPreferUnicast() })
	so.Setting.AddObserver(func(s *pc.Setting) {
		configuration.IPv6.Store(s.GetIpv6())
		configuration.FakeIPEnabled.Store(s.GetDns().GetFakedns() || s.GetServer().GetHijackDnsFakeip())
		if advanced := s.GetAdvancedConfig(); advanced != nil {
			if advanced.GetUdpBufferSize() > 2048 && advanced.GetUdpBufferSize() < 65535 {
				configuration.UDPBufferSize.Store(int(advanced.GetUdpBufferSize()))
			}

			if advanced.GetRelayBufferSize() > 2048 && advanced.GetRelayBufferSize() < 65535 {
				configuration.RelayBufferSize.Store(int(advanced.GetRelayBufferSize()))
			}
		}
	})

	// proxy access point/endpoint
	nodeManager := AddComponent(so, "node_manager", node.NewManager(PathGenerator.Node(so.ConfigPath)))
	register.RegisterPoint(func(x *protocol.Set, p netapi.Proxy) (netapi.Proxy, error) {
		return node.NewSet(x, nodeManager)
	})

	configuration.ProxyChain.Set(direct.Default)

	// local,remote,bootstrap dns
	dns := AddComponent(so, "resolver", resolver.NewResolver(configuration.ProxyChain))
	// bypass dialer and dns request
	st := AddComponent(so, "shunt", route.NewRoute(nodeManager.Outbound(), dns, opt.ProcessDumper))
	rc := route.NewRuleController(opt.BypassConfig, st)
	// connections' statistic & flow data

	flowCache := AddComponent(so, "flow_cache", ybbolt.NewCache(db, "flow_data"))
	stcs := AddComponent(so, "statistic", statistics.NewConnStore(flowCache, st))
	metrics.SetFlowCounter(stcs.Cache)
	hosts := AddComponent(so, "hosts", resolver.NewHosts(stcs, st))
	// wrap dialer and dns resolver to fake ip, if use
	fakedns := AddComponent(so, "fakedns", resolver.NewFakeDNS(hosts, hosts, db))
	resolverControl := resolver.NewResolverControl(so.ResolverConfig, hosts, fakedns, dns)
	// dns server/tun dns hijacking handler
	dnsServer := AddComponent(so, "dnsServer", resolver.NewDNSServer(fakedns))
	opt.Setting.AddObserver(func(s *pc.Setting) {
		dnsServer.SetServer(s.GetDns().GetServer())
	})
	// make dns flow across all proxy chain
	configuration.ProxyChain.Set(fakedns)
	// inbound server
	inbounds := AddComponent(so, "inbound_listener", inbound.NewListener(dnsServer, fakedns))
	opt.Setting.AddObserver(func(s *pc.Setting) {
		inbounds.SetHijackDnsFakeip(s.GetServer().GetHijackDnsFakeip())
		inbounds.SetSniff(s.GetServer().GetSniff().GetEnabled())
	})
	// tools
	tools := tools.NewTools(opt.Setting)
	mux := http.NewServeMux()

	mux.Handle("GET /metrics", promhttp.InstrumentMetricHandler(
		prometheus.DefaultRegisterer, promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
			DisableCompression: true,
			EnableOpenMetrics:  true,
		})))

	app := &appapi.Components{
		Start:          so,
		Mux:            mux,
		HttpListener:   httpListener,
		Tools:          tools,
		Node:           nodeManager.Node(),
		DB:             db,
		Subscribe:      nodeManager.Subscribe(),
		Connections:    stcs,
		Tag:            nodeManager.Tag(st.Tags),
		RuleController: rc,
		Inbound:        inbound.NewInboundControl(opt.Setting, inbounds),
		Resolver:       resolverControl,
	}

	// grpc and http server
	app.RegisterServer()

	tailscale.Mux.Store(app.Mux)

	return app, nil
}

var PathGenerator = pathGenerator{}

type pathGenerator struct{}

func (p pathGenerator) Lock(dir string) string   { return p.makeDir(filepath.Join(dir, "LOCK")) }
func (p pathGenerator) Node(dir string) string   { return p.makeDir(filepath.Join(dir, "node.json")) }
func (p pathGenerator) Config(dir string) string { return p.makeDir(filepath.Join(dir, "config.json")) }
func (p pathGenerator) Log(dir string) string {
	return p.makeDir(filepath.Join(dir, "log", "yuhaiin.log"))
}
func (pathGenerator) makeDir(s string) string {
	if _, err := os.Stat(s); errors.Is(err, os.ErrNotExist) {
		_ = os.MkdirAll(filepath.Dir(s), os.ModePerm)
	}

	return s
}
func (p pathGenerator) Cache(dir string) string { return p.makeDir(filepath.Join(dir, "cache")) }
