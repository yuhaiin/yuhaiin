package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/cache/pebble"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	"github.com/Asutorufa/yuhaiin/pkg/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/route"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/aead"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/drop"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2/v2"
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

func Start(so *StartOptions) (_ *AppInstance, err error) {
	configuration.DataDir.Store(so.ConfigPath)

	closers := &closers{}

	if closer, ok := so.StateStore.(io.Closer); ok {
		AddCloser(closers, "state_store", closer)
	}

	if migrator, ok := so.StateStore.(MigrationStore); ok {
		log.Info("start plain model migration")
		if err := migrator.Migrate(context.Background()); err != nil {
			_ = closers.Close()
			return nil, fmt.Errorf("plain model migration failed: %w", err)
		}
		log.Info("plain model migration finished")
	}

	logController := log.NewController()

	AddCloser(closers, "logger_controller", logController)

	pebbleCache, err := pebble.New(paths.PathGenerator.PebbleCache(so.ConfigPath))
	if err != nil {
		_ = closers.Close()
		return nil, fmt.Errorf("init pebble cache failed: %w", err)
	}
	AddCloser(closers, "pebble_cache", pebbleCache.Pebble())

	for _, f := range operators {
		f(closers)
	}

	log.Info("config", "path", so.ConfigPath)

	AddCloser(closers, "network_monitor", interfaces.StartNetworkMonitor())

	var settingsStore *plainstore.SettingsStore
	var backupStore *plainstore.BackupStore
	var resolverStore *plainstore.ResolverStore
	var resolverConfigStore *plainstore.ResolverConfigStore
	var routeSettingsStore *plainstore.RouteSettingsStore
	var routeRuleStore *plainstore.RouteRuleStore
	var routeListStore *plainstore.RouteListStore
	if sqlStore := so.StateStore; sqlStore != nil {
		db, err := sqlStore.SQLDB(context.Background())
		if err != nil {
			log.Error("open v2 sqlite store failed", "err", err)
		} else {
			settingsStore = plainstore.NewSettingsStore(db)
			backupStore = plainstore.NewBackupStore(db)
			resolverStore = plainstore.NewResolverStore(db)
			resolverConfigStore = plainstore.NewResolverConfigStore(db)
			routeSettingsStore = plainstore.NewRouteSettingsStore(db)
			routeRuleStore = plainstore.NewRouteRuleStore(db)
			routeListStore = plainstore.NewRouteListStore(db)
		}
	}
	settingsController := NewSettingsController(settingsStore, so.ConfigPath, logController)
	if settingsStore != nil {
		if settings, err := settingsController.Load(context.Background()); err != nil {
			log.Warn("load initial settings failed", "err", err)
		} else {
			settingsController.Apply(settings)
		}
	}
	// Read the configured ranges before importing the legacy Pebble FakeIP state.
	var initialFakeDNS contractresolver.FakeDNS
	if resolverConfigStore != nil {
		if config, err := resolverConfigStore.FakeDNS(context.Background()); err != nil {
			log.Warn("load initial fakedns config failed", "err", err)
		} else {
			initialFakeDNS = config
		}
	}
	if so.StateStore != nil {
		migrator, ok := so.StateStore.(PebbleMigrationStore)
		if !ok {
			_ = closers.Close()
			return nil, errors.New("state store does not support required startup legacy migration")
		}
		ctx := context.Background()
		log.Info("start legacy pebble state migration")
		if err := migrator.MigrateLegacyPebble(
			ctx,
			pebbleCache,
			configuration.GetFakeIPRange(initialFakeDNS.IPv4Range, false),
			configuration.GetFakeIPRange(initialFakeDNS.IPv6Range, true),
		); err != nil {
			_ = closers.Close()
			return nil, fmt.Errorf("migrate legacy Pebble state failed: %w", err)
		}
		log.Info("legacy pebble state migration finished")
	}
	configuration.ProxyChain.Set(direct.Default)
	// Proxy and DNS runtime objects are created only after every legacy store
	// has been migrated into the plain SQLite model.
	nodeRuntime := AddCloser(closers, "node_runtime", node.NewNodeRuntime(paths.PathGenerator.State(so.ConfigPath)))
	dns := AddCloser(closers, "resolver", resolver.NewResolver(configuration.ProxyChain))
	list := AddCloser(closers, "lists", route.NewLists(routeListStore, routeSettingsStore, so.ConfigPath))
	// bypass dialer and dns request
	router := AddCloser(closers, "router", route.NewRoute(nodeRuntime, dns, list, so.ProcessDumper))
	rules := route.NewRules(routeRuleStore, routeSettingsStore, router)
	// connections' statistic & flow data
	stcs := AddCloser(closers, "statistic", statistics.NewSQLiteConnStore(
		paths.PathGenerator.State(so.ConfigPath),
		router,
	))
	metrics.SetFlowCounter(stcs.Cache)
	hosts := AddCloser(closers, "hosts", resolver.NewHosts(stcs, router))
	// Wrap dialer and DNS resolver with the migrated FakeIP pools.
	fakedns, err := resolver.NewFakeDNS(
		hosts,
		hosts,
		paths.PathGenerator.State(so.ConfigPath),
		initialFakeDNS,
	)
	if err != nil {
		_ = closers.Close()
		return nil, fmt.Errorf("init fake dns failed: %w", err)
	}
	AddCloser(closers, "fakedns", fakedns)
	log.Info("init resolver controller")
	resolverCtr := resolver.NewResolverCtr(resolverStore, resolverConfigStore, hosts, fakedns, dns)
	log.Info("init resolver controller finished")

	// make dns flow across all proxy chain
	configuration.ProxyChain.Set(fakedns)
	configuration.ResolverChain.Set(fakedns)
	list.SetProxy(fakedns)

	// inbound server
	inbounds := AddCloser(closers, "inbound_listener", inbound.NewInbound(fakedns, inbound.WithDNSAgent(fakedns)))
	dialer.SkipInterface = inbounds.Interfaces
	// tools
	tools := NewTools(logController)
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
		Node:         nodeRuntime,
		NodeRuntime:  nodeRuntime,
		Connections:  statistics.NewConnectionMonitor(stcs),
		Lists:        route.NewContractListController(list),
		Rules:        route.NewContractRuleController(rules),
		Resolver:     resolver.NewContractController(resolverCtr),
		ResolverCfg:  resolver.NewContractConfigController(resolverCtr),
		Setting:      settingsController,
		Inbound:      inbounds,
		closers:      closers,
	}

	app.Backup = AddCloser(closers, "backup", NewBackup(backupStore, so.ConfigPath, app, fakedns))

	app.RegisterServer()

	tailscale.Mux.Store(app.Mux)

	return app, nil
}

type PebbleMigrationStore interface {
	MigrateLegacyPebble(context.Context, cache.Cache, netip.Prefix, netip.Prefix) error
}
