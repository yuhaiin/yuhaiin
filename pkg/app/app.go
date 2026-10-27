package app

import (
	"context"
	"fmt"
	"io"
	"net/http"

	backupapp "github.com/Asutorufa/yuhaiin/pkg/app/backup"
	recovery "github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/response"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/aead"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/amneziawg"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/anyconnect"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/drop"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fortinet"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/globalprotect"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2/v2"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/ikev2"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/l2tp"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/masque"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mixed"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mock"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mux"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/nebula"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/openvpn"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/reality"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks4a"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/softether"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/ssh"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/sstp"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/trojan"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vless"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/zerotier"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	"github.com/Asutorufa/yuhaiin/pkg/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/route"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var operators = []func(*closers){}

func AddCloser[T io.Closer](a *closers, name string, t T) T {
	log.Info("add closer", "name", name)
	a.AddCloser(name, t)
	return t
}

func Start(so *StartOptions) (_ *AppInstance, err error) {
	if err := recovery.CheckStartup(so.ConfigPath, so.RecoveryStartupID); err != nil {
		return nil, err
	}
	configuration.DataDir.Store(so.ConfigPath)

	ctx := so.Context
	if ctx == nil {
		ctx = context.Background()
	}

	closers := &closers{}

	if closer, ok := so.StateStore.(io.Closer); ok {
		AddCloser(closers, "state_store", closer)
	}

	if migrator, ok := so.StateStore.(MigrationStore); ok {
		log.Info("initialize sqlite schema")
		if err := migrator.Migrate(ctx); err != nil {
			_ = closers.Close()
			return nil, fmt.Errorf("sqlite initialization failed: %w", err)
		}
		log.Info("sqlite schema ready")
	}

	logController := log.NewController()

	AddCloser(closers, "logger_controller", logController)

	for _, f := range operators {
		f(closers)
	}

	log.Info("config", "path", so.ConfigPath)

	AddCloser(closers, "network_monitor", interfaces.StartNetworkMonitor())

	var inboundConfigStore *plainstore.InboundStore
	var settingsStore *plainstore.SettingsStore
	var backupStore *backupstore.Store
	var resolverStore *plainstore.ResolverStore
	var resolverConfigStore *plainstore.ResolverConfigStore
	var routeSettingsStore *plainstore.RouteSettingsStore
	var routeRuleStore *plainstore.RouteRuleStore
	var routeListStore *plainstore.RouteListStore
	var gatewayStore *plainstore.GatewayStore
	if sqlStore := so.StateStore; sqlStore != nil {
		db, err := sqlStore.SQLDB(ctx)
		if err != nil {
			if ctx.Err() != nil {
				_ = closers.Close()
				return nil, ctx.Err()
			}
			log.Error("open v2 sqlite store failed", "err", err)
		} else {
			inboundConfigStore = plainstore.NewInboundStore(db)
			settingsStore = plainstore.NewSettingsStore(db)
			backupStore = backupstore.New(db)
			resolverStore = plainstore.NewResolverStore(db)
			resolverConfigStore = plainstore.NewResolverConfigStore(db)
			routeSettingsStore = plainstore.NewRouteSettingsStore(db)
			routeRuleStore = plainstore.NewRouteRuleStore(db)
			routeListStore = plainstore.NewRouteListStore(db)
			gatewayStore = plainstore.NewGatewayStore(db)
		}
	}
	settingsController := NewSettingsController(settingsStore, so.ConfigPath, logController)
	if settingsStore != nil {
		if settings, err := settingsController.Load(ctx); err != nil {
			if ctx.Err() != nil {
				_ = closers.Close()
				return nil, ctx.Err()
			}
			log.Warn("load initial settings failed", "err", err)
		} else {
			settingsController.Apply(settings)
		}
	}
	// Load FakeDNS settings from the SQLite state store.
	var initialFakeDNS contractresolver.FakeDNS
	if resolverConfigStore != nil {
		if config, err := resolverConfigStore.FakeDNS(ctx); err != nil {
			if ctx.Err() != nil {
				_ = closers.Close()
				return nil, ctx.Err()
			}
			log.Warn("load initial fakedns config failed", "err", err)
		} else {
			initialFakeDNS = config
		}
	}
	if err := ctx.Err(); err != nil {
		_ = closers.Close()
		return nil, err
	}

	configuration.ProxyChain.Set(direct.Default)
	// Proxy and DNS runtime objects are created after SQLite state initialization.
	nodeRuntime := AddCloser(closers, "node_runtime", node.NewNodeRuntime(paths.PathGenerator.State(so.ConfigPath), node.RequireProbePolicy()))
	dns := AddCloser(closers, "resolver", resolver.NewResolver(configuration.ProxyChain))
	list := AddCloser(closers, "lists", route.NewLists(routeListStore, routeSettingsStore, so.ConfigPath))
	// bypass dialer and dns request
	router := AddCloser(closers, "router", route.NewRoute(nodeRuntime, dns, list, so.ProcessDumper))
	rules := AddCloser(closers, "rules", route.NewRules(routeRuleStore, routeSettingsStore, router))
	// connections' statistic & flow data
	stcs := AddCloser(closers, "statistic", statistics.NewSQLiteConnStore(
		paths.PathGenerator.State(so.ConfigPath),
		router,
	))
	metrics.SetFlowCounter(stcs.Cache)
	var userUsage httpapi.UserUsage
	var usageRecorder *statistics.UserUsage
	var localGatewayAudit func(*netapi.Context, string, bool)
	if so.ProxyAuthentication != nil {
		recorder, err := stcs.EnableUserUsage(statistics.DefaultUsageOptions())
		if err != nil {
			_ = closers.Close()
			return nil, fmt.Errorf("initialize user usage: %w", err)
		}
		userUsage = recorder
		usageRecorder = recorder
		localGatewayAudit = stcs.RecordGatewayAction
		if reporting, ok := so.ProxyAuthentication.(interface{ SetFailureObserver(func(string, string)) }); ok {
			reporting.SetFailureObserver(recorder.AuthenticationFailure)
		}
	}
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
	responses := response.New(fakedns)
	dnsServer := AddCloser(closers, "dns server", resolver.NewDNSServer(responses))
	log.Info("init resolver controller")
	resolverCtr := resolver.NewResolverCtr(resolverStore, resolverConfigStore, hosts, fakedns, dns, responses, dnsServer)
	log.Info("init resolver controller finished")

	// make dns flow across all proxy chain
	configuration.ProxyChain.Set(fakedns)
	configuration.ResolverChain.Set(responses)
	list.SetProxy(fakedns)

	// inbound server
	var gatewayManager *gateway.Manager
	if gatewayStore != nil {
		authority, err := gateway.NewAuthority(ctx, gatewayStore)
		if err != nil {
			_ = closers.Close()
			return nil, err
		}
		gatewayManager, err = gateway.NewManager(ctx, gatewayStore, authority, func(ctx context.Context, a netapi.Address, target contractroute.Target) (gateway.Selection, error) {
			a = hosts.RecoverDestination(ctx, fakedns.RecoverDestination(ctx, a))
			proxy, destination, err := router.ResolveTCP(route.WithoutGateway(ctx), a, target)
			if err != nil {
				return gateway.Selection{}, err
			}
			label := netapi.GetContext(ctx).NodeName
			if label == "" {
				label = netapi.GetContext(ctx).ConnOptions().RouteMode()
			}
			return gateway.Selection{Label: label, Identity: gateway.ProxyIdentity(proxy), Proxy: selectedGatewayProxy{Proxy: proxy, connections: stcs, fakeDNS: fakedns}, Destination: destination}, nil
		}, gateway.WithDestinationRecovery(fakedns.RecoverDestination), gateway.WithProcessLookup(router.PrepareGatewayContext), gateway.WithLocalAudit(localGatewayAudit))
		if err != nil {
			_ = closers.Close()
			return nil, fmt.Errorf("initialize gateway: %w", err)
		}
		AddCloser(closers, "gateway", gatewayManager)
	}
	var interceptionOptions []inbound.Option
	if gatewayManager != nil {
		router.SetGatewayHandler(func(ctx context.Context, address netapi.Address) netapi.Address {
			return hosts.RecoverDestination(ctx, fakedns.RecoverDestination(ctx, address))
		}, gatewayManager.InterceptGateway)
		interceptionOptions = append(interceptionOptions, inbound.WithInterceptor(router))
	}
	interceptionOptions = append(interceptionOptions, inbound.WithAuthentication(so.ProxyAuthentication), inbound.WithUserUsage(usageRecorder), inbound.WithDNSAgent(dnsServer), inbound.WithFakeIPRangeSource(fakedns))
	if inboundConfigStore != nil {
		interceptionOptions = append(interceptionOptions, inbound.WithIngressStatisticsStore(inboundConfigStore))
	}
	if nodeRuntime != nil {
		nodeRuntime.SetCredentialResolver(so.UpstreamCredentials)
	}
	inbounds := AddCloser(closers, "inbound_listener", inbound.NewInbound(fakedns, interceptionOptions...))
	if err := inbounds.RestoreStatistics(ctx); err != nil {
		_ = closers.Close()
		return nil, fmt.Errorf("restore inbound ingress statistics: %w", err)
	}
	dialer.SkipInterface = inbounds.Interfaces
	// tools
	tools := NewTools(logController)
	mux := http.NewServeMux()
	metricsGatherer := prometheus.DefaultGatherer
	registry := prometheus.NewRegistry()
	registry.MustRegister(nodeRuntime.Metrics())
	if gatewayManager != nil {
		registry.MustRegister(gatewayManager.Metrics())
	}
	metricsGatherer = prometheus.Gatherers{metricsGatherer, registry}

	mux.Handle("GET /metrics", promhttp.InstrumentMetricHandler(
		prometheus.DefaultRegisterer, promhttp.HandlerFor(metricsGatherer, promhttp.HandlerOpts{
			DisableCompression: true,
			EnableOpenMetrics:  true,
		})))

	app := &AppInstance{
		Gateway:       gatewayManager,
		StartOptions:  so,
		Mux:           mux,
		Tools:         tools,
		Diagnostics:   newDiagnostics(inboundConfigStore, inbounds, nodeRuntime, hosts, rules),
		Node:          nodeRuntime,
		NodeRuntime:   nodeRuntime,
		Connections:   statistics.NewConnectionMonitor(stcs),
		UserUsage:     userUsage,
		Lists:         route.NewContractListController(list),
		Rules:         route.NewContractRuleController(rules),
		Resolver:      resolver.NewContractController(resolverCtr),
		FakeIP:        fakedns,
		ResolverCache: resolver.NewContractController(resolverCtr),
		ResolverCfg:   resolver.NewContractConfigController(resolverCtr),
		Setting:       settingsController,
		Inbound:       inbounds,
		closers:       closers,
	}

	backup := backupapp.New(backupStore, so.ConfigPath, so.RecoveryMaintenance, fakedns)
	app.Backup = AddCloser(closers, "backup", backup)
	registry.MustRegister(backup.Metrics())

	if err := ctx.Err(); err != nil {
		_ = app.Close()
		return nil, err
	}
	if err := app.RegisterServer(ctx); err != nil {
		_ = app.Close()
		return nil, err
	}
	// RegisterServer hydrates route and traffic-control snapshots before probes
	// may construct a client or issue any traffic. There is no startup gap with
	// an unlimited default policy, even when persisted schedules are enabled.
	nodeRuntime.SetProbePolicy(node.ProbePolicy{
		Ready: func() bool { return inbounds.ProbePolicyReady() && rules.HasActiveSnapshot() },
		Wrap: func(ctx context.Context, proxy netapi.Proxy) netapi.Proxy {
			return inbounds.ProbeProxy(ctx, proxy, func(ctx context.Context, a netapi.Address) (netapi.Address, error) {
				a = hosts.RecoverDestination(ctx, fakedns.RecoverDestination(ctx, a))
				return router.PrepareProbe(ctx, a)
			})
		},
	})

	tailscale.Mux.Store(app.Mux)

	return app, nil
}
