package app

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/chore"
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
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/route"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	ybbolt "github.com/Asutorufa/yuhaiin/pkg/utils/cache/bbolt"
	"github.com/Asutorufa/yuhaiin/pkg/utils/goos"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.etcd.io/bbolt"
	bolterr "go.etcd.io/bbolt/errors"

	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/aead"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/drop"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/grpc"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mock"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mux"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/reality"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/reverse"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr"
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

var operators = []func(*closers){}

func AddCloser[T io.Closer](a *closers, name string, t T) T {
	a.AddCloser(name, t)
	return t
}

func OpenBboltDB(path string) (*bbolt.DB, error) {
	db, err := bbolt.Open(path, os.ModePerm, &bbolt.Options{
		Timeout: time.Second * 2,
		Logger:  ybbolt.BBoltDBLogger{},
	})
	switch err {
	case bolterr.ErrInvalid, bolterr.ErrChecksum, bolterr.ErrVersionMismatch:
		if err = os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove invalid cache file failed: %w", err)
		}
		log.Warn("remove invalid cache file and create new one")
		return bbolt.Open(path, os.ModePerm, &bbolt.Options{Timeout: time.Second})
	}

	// set big batch delay to reduce sync for fake dns and connection cache
	db.MaxBatchDelay = time.Millisecond * 300

	return db, err
}

func Start(so *StartOptions) (_ *AppInstance, err error) {
	configuration.DataDir.Store(so.ConfigPath)

	closers := &closers{}

	cache := so.Cache
	if cache == nil {
		db, err := OpenBboltDB(tools.PathGenerator.Cache(so.ConfigPath))
		if err != nil {
			return nil, fmt.Errorf("init bbolt cache failed: %w", err)
		}
		closers.AddCloser("bbolt_db", db)
		cache = ybbolt.NewCache(db)
	}

	for _, f := range operators {
		f(closers)
	}

	chore := chore.NewChore(so.ChoreConfig, updateConfiguration(so))

	log.Info("config", "path", so.ConfigPath)

	// proxy access point/endpoint
	nodeManager := AddCloser(closers, "node_manager", node.NewManager(tools.PathGenerator.Node(so.ConfigPath)))
	register.RegisterPoint(func(x *protocol.Set, p netapi.Proxy) (netapi.Proxy, error) {
		return node.NewSet(x, nodeManager)
	})

	configuration.ProxyChain.Set(direct.Default)

	// local,remote,bootstrap dns
	dns := AddCloser(closers, "resolver", resolver.NewResolver(configuration.ProxyChain))
	list := route.NewLists(so.BypassConfig)
	// bypass dialer and dns request
	router := AddCloser(closers, "router", route.NewRoute(nodeManager.Outbound(), dns, list, so.ProcessDumper))
	list.SetProxy(router)
	rules := route.NewRules(so.BypassConfig, router)
	// connections' statistic & flow data

	flowCache := AddCloser(closers, "flow_cache", cache.NewCache("flow_data"))
	connectionCache := AddCloser(closers, "connection_cache", cache.NewCache("connection_data"))
	historyCache := AddCloser(closers, "history_cache", cache.NewCache("history_data"))
	stcs := AddCloser(closers, "statistic",
		statistics.NewConnStore(flowCache, historyCache, connectionCache, router))
	metrics.SetFlowCounter(stcs.Cache)
	hosts := AddCloser(closers, "hosts", resolver.NewHosts(stcs, router))
	// wrap dialer and dns resolver to fake ip, if use
	fakedns := AddCloser(closers, "fakedns", resolver.NewFakeDNS(hosts, hosts, cache))
	// dns server/tun dns hijacking handler
	dnsServer := AddCloser(closers, "dnsServer", resolver.NewDNSServer(fakedns))
	resolverCtr := resolver.NewResolverCtr(so.ResolverConfig, hosts, fakedns, dns, dnsServer)

	// make dns flow across all proxy chain
	configuration.ProxyChain.Set(fakedns)
	// inbound server
	inbounds := AddCloser(closers, "inbound_listener", inbound.NewInbound(dnsServer, fakedns))
	// tools
	tools := tools.NewTools(so.ChoreConfig)
	mux := http.NewServeMux()

	mux.Handle("GET /metrics", promhttp.InstrumentMetricHandler(
		prometheus.DefaultRegisterer, promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
			DisableCompression: true,
			EnableOpenMetrics:  true,
		})))

	app := &AppInstance{
		StartOptions:   so,
		Mux:            mux,
		Tools:          tools,
		Node:           nodeManager.Node(),
		Subscribe:      nodeManager.Subscribe(),
		Connections:    stcs,
		Tag:            nodeManager.Tag(router.Tags),
		RuleController: gc.UnimplementedBypassServer{},
		Lists:          list,
		Rules:          rules,
		Inbound:        inbound.NewInboundCtr(so.InboundConfig, inbounds),
		Resolver:       resolverCtr,
		Setting:        chore,
		closers:        closers,
	}

	app.Backup = AddCloser(closers, "backup", NewBackup(so.BackupConfig, app, fakedns))

	// grpc and http server
	app.RegisterServer()

	tailscale.Mux.Store(app.Mux)

	return app, nil
}

type resultCache[K any, T comparable] struct {
	do               func(K) (T, error)
	expireTime       int64
	successThreshold int32
	currentSuccess   atomic.Int32
	lastTime         atomic.Int64
	Data             atomicx.Value[T]
}

func NewResultCache[K any, T comparable](do func(K) (T, error), expireTime int64, successThreshold int32) *resultCache[K, T] {
	return &resultCache[K, T]{
		do:               do,
		expireTime:       expireTime,
		successThreshold: successThreshold,
	}
}

func (c *resultCache[K, T]) Get(x K) (T, error) {

	now := system.CheapNowNano()

	if c.currentSuccess.Load() >= c.successThreshold && now-c.lastTime.Load() <= c.expireTime {
		if data := c.Data.Load(); data != *new(T) {
			return data, nil
		}
	}

	data, err := c.do(x)
	if err != nil {
		c.currentSuccess.Store(0)
		return *new(T), err
	}

	c.Data.Store(data)
	c.lastTime.Store(now)
	c.currentSuccess.Add(1)

	return data, nil
}

func setDefaultInterfaceName(defaultInterface string, useDefaultInterface bool) {
	// default interface
	iface := ""

	var mu sync.RWMutex

	checkInterface := func(x string) (string, error) {
		if _, err := net.InterfaceByName(x); err != nil {
			return "", err
		}

		return x, nil
	}

	resultCache := NewResultCache(checkInterface, int64(time.Minute), 5)

	dialer.DefaultInterfaceName = func() string {
		if goos.IsAndroid == 1 || !useDefaultInterface {
			return defaultInterface
		}

		mu.RLock()
		x := iface
		mu.RUnlock()

		if x != "" {
			if _, err := resultCache.Get(x); err == nil {
				return x
			}

			mu.Lock()
			iface = ""
			mu.Unlock()
		}

		mu.Lock()
		defer mu.Unlock()

		ifacestr, err := interfaces.DefaultRouteInterface()
		if err != nil {
			log.Error("get default interface failed", "error", err)
		} else {
			log.Info("use default interface", "interface", ifacestr)
			iface = ifacestr
		}

		return ifacestr
	}
}

func updateConfiguration(so *StartOptions) func(s *pc.Setting) {
	return func(s *pc.Setting) {
		log.Set(s.GetLogcat(), tools.PathGenerator.Log(so.ConfigPath))
		configuration.IgnoreDnsErrorLog.Store(s.GetLogcat().GetIgnoreDnsError())
		configuration.IgnoreTimeoutErrorLog.Store(s.GetLogcat().GetIgnoreTimeoutError())

		sysproxy.Update(s)

		setDefaultInterfaceName(s.GetNetInterface(), s.GetUseDefaultInterface())

		dialer.DefaultIPv6PreferUnicastLocalAddr = s.GetIpv6LocalAddrPreferUnicast()

		configuration.IPv6.Store(s.GetIpv6())
		configuration.FakeIPEnabled.Store(s.GetDns().GetFakedns() || s.GetServer().GetHijackDnsFakeip())
		if advanced := s.GetAdvancedConfig(); advanced != nil {
			if advanced.GetUdpBufferSize() > 2048 && advanced.GetUdpBufferSize() < 65535 {
				configuration.UDPBufferSize.Store(int(advanced.GetUdpBufferSize()))
			}

			if advanced.GetRelayBufferSize() > 2048 && advanced.GetRelayBufferSize() < 65535 {
				configuration.RelayBufferSize.Store(int(advanced.GetRelayBufferSize()))
			}

			udpRingBufferSize := s.GetAdvancedConfig().GetUdpRingbufferSize()
			if udpRingBufferSize >= 100 && udpRingBufferSize <= 5000 {
				configuration.MaxUDPUnprocessedPackets.Store(int(udpRingBufferSize))
			}
		}
	}
}
