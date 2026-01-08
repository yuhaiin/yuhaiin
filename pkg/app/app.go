package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/cache/badger"
	ybbolt "github.com/Asutorufa/yuhaiin/pkg/cache/bbolt"
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
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	pn "github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/route"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.etcd.io/bbolt"
	bolterr "go.etcd.io/bbolt/errors"
	"google.golang.org/protobuf/types/known/emptypb"

	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/aead"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/drop"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/grpc"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/masque"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mock"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mux"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
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
	log.Info("add closer", "name", name)
	a.AddCloser(name, t)
	return t
}

func OpenBboltDB(path string) (*bbolt.DB, error) {
	start := time.Now()
	defer func() { log.Info("open bbolt db", "path", path, "cost", time.Since(start)) }()

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
	if err != nil {
		return nil, err
	}

	// set big batch delay to reduce sync for fake dns and connection cache
	db.MaxBatchDelay = time.Millisecond * 300

	return db, err
}

func Start(so *StartOptions) (_ *AppInstance, err error) {
	configuration.DataDir.Store(so.ConfigPath)

	closers := &closers{}

	logController := log.NewController()

	choreService := chore.NewChore(so.ChoreConfig,
		func(s *config.Setting) { updateConfiguration(so, s, logController) })

	config, err := choreService.Load(context.Background(), &emptypb.Empty{})
	if err == nil {
		updateConfiguration(so, config, logController)
	}

	AddCloser(closers, "logger_controller", logController)

	badgerCache, err := badger.New(tools.PathGenerator.BadgerCache(so.ConfigPath))
	if err != nil {
		_ = closers.Close()
		return nil, fmt.Errorf("init badger cache failed: %w", err)
	}
	AddCloser(closers, "badger_cache", badgerCache.Badger())

	migrateDB(badgerCache, so.ConfigPath)

	for _, f := range operators {
		f(closers)
	}

	log.Info("config", "path", so.ConfigPath)

	AddCloser(closers, "network_monitor", interfaces.StartNetworkMonitor())

	// proxy access point/endpoint
	nodeManager := AddCloser(closers, "node_manager", node.NewManager(tools.PathGenerator.Node(so.ConfigPath)))
	register.RegisterPoint(func(x *pn.Set, p netapi.Proxy) (netapi.Proxy, error) {
		return node.NewSet(x, nodeManager)
	})

	configuration.ProxyChain.Set(direct.Default)

	// local,remote,bootstrap dns
	dns := AddCloser(closers, "resolver", resolver.NewResolver(configuration.ProxyChain))
	list := AddCloser(closers, "lists", route.NewLists(so.BypassConfig))
	// bypass dialer and dns request
	router := AddCloser(closers, "router", route.NewRoute(nodeManager.Outbound(), dns, list, so.ProcessDumper))
	rules := route.NewRules(so.BypassConfig, router)
	// connections' statistic & flow data

	stcs := AddCloser(closers, "statistic", statistics.NewConnStore(badgerCache, router))
	metrics.SetFlowCounter(stcs.Cache)
	hosts := AddCloser(closers, "hosts", resolver.NewHosts(stcs, router))
	// wrap dialer and dns resolver to fake ip, if use
	fakedns := AddCloser(closers, "fakedns", resolver.NewFakeDNS(hosts, hosts, badgerCache))
	resolverCtr := resolver.NewResolverCtr(so.ResolverConfig, hosts, fakedns, dns)

	// make dns flow across all proxy chain
	configuration.ProxyChain.Set(fakedns)
	configuration.ResolverChain.Set(fakedns)
	list.SetProxy(fakedns)

	// inbound server
	inbounds := AddCloser(closers, "inbound_listener", inbound.NewInbound(fakedns, inbound.WithDNSAgent(fakedns)))
	dialer.SkipInterface = inbounds.Interfaces
	// tools
	tools := chore.NewTools(so.ChoreConfig, logController)
	mux := http.NewServeMux()

	mux.Handle("GET /metrics", promhttp.InstrumentMetricHandler(
		prometheus.DefaultRegisterer, promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
			DisableCompression: true,
			EnableOpenMetrics:  true,
		})))

	app := &AppInstance{
		StartOptions: so,
		Mux:          mux,
		Tools:        tools,
		Node:         nodeManager.Node(),
		Subscribe:    nodeManager.Subscribe(),
		Connections:  stcs,
		Tag:          nodeManager.Tag(router.Tags),
		Lists:        list,
		Rules:        rules,
		Inbound:      inbound.NewInboundCtr(so.InboundConfig, inbounds),
		Resolver:     resolverCtr,
		Setting:      choreService,
		closers:      closers,
	}

	app.Backup = AddCloser(closers, "backup", NewBackup(so.BackupConfig, app, fakedns))

	// grpc and http server
	app.RegisterServer()

	tailscale.Mux.Store(app.Mux)

	return app, nil
}

func updateConfiguration(so *StartOptions, s *config.Setting, logController *log.Controller) {
	logController.Set(s.GetLogcat(), tools.PathGenerator.Log(so.ConfigPath))
	slog.SetDefault(slog.New(log.Default()))

	configuration.IgnoreDnsErrorLog.Store(s.GetLogcat().GetIgnoreDnsError())
	configuration.IgnoreTimeoutErrorLog.Store(s.GetLogcat().GetIgnoreTimeoutError())

	sysproxy.Update(chore.GetSystemHttpHost(s), chore.GetSystemSocks5Host(s))

	defaultInterfaceName := s.GetNetInterface()
	useDefaultInterface := s.GetUseDefaultInterface()

	if useDefaultInterface && runtime.GOOS != "android" {
		dialer.DefaultInterfaceName = func() string { return "" }
	} else {
		if defaultInterfaceName == "default" {
			dialer.DefaultInterfaceName = interfaces.DefaultInterfaceName
		} else {
			dialer.DefaultInterfaceName = func() string { return defaultInterfaceName }
		}
	}

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

		happyeyeballsSemaphore := s.GetAdvancedConfig().GetHappyeyeballsSemaphore()

		if int64(happyeyeballsSemaphore) != dialer.DefaultHappyEyeballsv2Dialer.Load().SemaphoreWeight() {
			if happyeyeballsSemaphore > 0 && happyeyeballsSemaphore < 10 {
				log.Warn("happyeyeballsSemaphore is less than 10, set to 10")
				happyeyeballsSemaphore = 10
			}

			log.Info("update happyeyeballs semaphore", "value", happyeyeballsSemaphore)

			dialer.DefaultHappyEyeballsv2Dialer.Store(dialer.NewDefaultHappyEyeballsv2Dialer(
				dialer.WithHappyEyeballsSemaphore[net.Conn](semaphore.NewSemaphore(int64(happyeyeballsSemaphore)))))
		}
	}
}

func migrateDB(badgerCache *badger.Cache, path string) {
	v, err := badgerCache.Get(badger.MigrateKey)
	if err != nil {
		log.Warn("get badger migrate key failed", "err", err)
		return
	}

	if len(v) != 0 && v[0] == 1 {
		log.Info("check already migrated db, skip")
		return
	}

	db, err := OpenBboltDB(tools.PathGenerator.Cache(path))
	if err != nil {
		log.Warn("open old bbolt db failed, skip migrate db")
		return
	}
	defer db.Close()

	ybc := ybbolt.NewCache(db)

	migrate := func(bucketName string) {
		err = badgerCache.NewCache(bucketName).Batch(func(txn cache.Batch) error {
			var err error
			ybc.NewCache(bucketName).Range(func(key, value []byte) bool {
				err = txn.Put(key, value)
				return err == nil
			})
			return err
		})
		if err != nil {
			log.Warn("migrate bucket failed", "bucket", bucketName, "err", err)
		}
	}

	migrate("flow_data")
	migrate("fakedns_cachev6")
	migrate("fakedns_cache")

	badgerCache.Put(badger.MigrateKey, []byte{1})
}
