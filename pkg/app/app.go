package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	web "github.com/Asutorufa/yuhaiin/internal/http"
	"github.com/Asutorufa/yuhaiin/internal/shunt"
	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/app/config"
	"github.com/Asutorufa/yuhaiin/pkg/app/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/app/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/app/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"go.etcd.io/bbolt"
	"google.golang.org/grpc"
)

type StartOpt struct {
	ConfigPath string
	Host       string
	Setting    config.Setting

	ProcessDumper listener.ProcessDumper
	GRPCServer    *grpc.Server
}

func (s *StartOpt) addObserver(observers ...any) {
	for _, observer := range observers {
		if z, ok := observer.(config.Observer); ok {
			s.Setting.AddObserver(z)
		}
	}
}

type StartResponse struct {
	HttpListener net.Listener

	Mux *http.ServeMux

	Node *node.Nodes

	closers []io.Closer
}

func (s *StartResponse) Close() error {
	for _, z := range s.closers {
		z.Close()
	}
	log.Close()
	sysproxy.Unset()
	return nil
}

func initBboltDB(path string) (*bbolt.DB, error) {
	db, err := bbolt.Open(path, os.ModePerm, &bbolt.Options{Timeout: time.Second * 2})
	switch err {
	case bbolt.ErrInvalid, bbolt.ErrChecksum, bbolt.ErrVersionMismatch:
		if err = os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove invalid cache file failed: %w", err)
		}
		log.Info("remove invalid cache file and create new one")
		return bbolt.Open(path, os.ModePerm, &bbolt.Options{Timeout: time.Second})
	}

	return db, err
}

func Start(opt StartOpt) (StartResponse, error) {
	db, err := initBboltDB(PathGenerator.Cache(opt.ConfigPath))
	if err != nil {
		return StartResponse{}, fmt.Errorf("init bbolt cache failed: %w", err)
	}

	lis, err := net.Listen("tcp", opt.Host)
	if err != nil {
		return StartResponse{}, err
	}

	fmt.Println(version.Art)
	log.Info("config", "path", opt.ConfigPath, "grpc&http host", opt.Host)

	opt.addObserver(config.ObserverFunc(sysproxy.Update))
	opt.addObserver(config.ObserverFunc(func(s *pc.Setting) { log.Set(s.GetLogcat(), PathGenerator.Log(opt.ConfigPath)) }))
	opt.addObserver(config.ObserverFunc(func(s *pc.Setting) { dialer.DefaultInterfaceName = s.GetNetInterface() }))

	filestore := node.NewFileStore(PathGenerator.Node(opt.ConfigPath))
	// proxy access point/endpoint
	nodeService := node.NewNodes(filestore)
	subscribe := node.NewSubscribe(filestore)
	tag := node.NewTag(filestore)

	// make dns flow across all proxy chain
	appDialer := &storeProxy{}

	// local,remote,bootstrap dns
	bootstrap := resolver.NewBootstrap(appDialer)
	stOpt := shunt.Opts{
		DirectDialer:   direct.Default,
		DirectResolver: resolver.NewLocal(appDialer),
		ProxyDialer:    nodeService,
		ProxyResolver:  resolver.NewRemote(appDialer),
		BlockDialer:    reject.Default,
		BLockResolver:  proxy.ErrorResolver(func(domain string) error { return proxy.NewBlockError(-2, domain) }),
		DefaultMode:    bypass.Mode_proxy,
	}

	opt.addObserver(bootstrap, stOpt.DirectResolver, stOpt.ProxyResolver)

	// bypass dialer and dns request
	st := shunt.NewShunt(stOpt)
	opt.addObserver(st)

	// connections' statistic & flow data
	stcs := statistics.NewConnStore(cache.NewCache(db, "flow_data"), st, opt.ProcessDumper)

	hosts := resolver.NewHosts(stcs, st)
	opt.addObserver(hosts)

	// wrap dialer and dns resolver to fake ip, if use
	fakedns := resolver.NewFakeDNS(hosts, hosts, cache.NewCache(db, "fakedns_cache"))
	opt.addObserver(fakedns)

	// dns server/tun dns hijacking handler
	dnsServer := resolver.NewDNSServer(fakedns)
	opt.addObserver(dnsServer)

	// give dns a dialer
	appDialer.Proxy = fakedns

	ss := inbound.NewHandler(fakedns)

	// http/socks5/redir/tun server
	listener := inbound.NewListener(&listener.Opts[listener.IsProtocol_Protocol]{DNSHandler: dnsServer, Handler: ss})
	opt.addObserver(listener)

	// http page
	mux := http.NewServeMux()
	web.Httpserver(web.HttpServerOption{
		Mux:         mux,
		NodeServer:  nodeService,
		Subscribe:   subscribe,
		Connections: stcs,
		Config:      opt.Setting,
		Tag:         tag,
		Shunt:       st,
	})

	// grpc server
	if opt.GRPCServer != nil {
		opt.GRPCServer.RegisterService(&gc.ConfigDao_ServiceDesc, opt.Setting)
		opt.GRPCServer.RegisterService(&gn.Node_ServiceDesc, nodeService)
		opt.GRPCServer.RegisterService(&gn.Subscribe_ServiceDesc, subscribe)
		opt.GRPCServer.RegisterService(&gs.Connections_ServiceDesc, stcs)
		opt.GRPCServer.RegisterService(&gn.Tag_ServiceDesc, tag)
	}

	return StartResponse{
		HttpListener: lis,
		Mux:          mux,
		Node:         nodeService,
		closers:      []io.Closer{stcs, listener, bootstrap, st.DirectResolver, st.ProxyResolver, dnsServer, db, ss},
	}, nil
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
		os.MkdirAll(filepath.Dir(s), os.ModePerm)
	}

	return s
}
func (p pathGenerator) Cache(dir string) string { return p.makeDir(filepath.Join(dir, "cache")) }

type storeProxy struct{ proxy.Proxy }

func (w *storeProxy) Conn(ctx context.Context, addr proxy.Address) (net.Conn, error) {
	return w.Proxy.Conn(proxy.NewStore(ctx), addr)
}

func (w *storeProxy) PacketConn(ctx context.Context, addr proxy.Address) (net.PacketConn, error) {
	return w.Proxy.PacketConn(proxy.NewStore(ctx), addr)
}

func (w *storeProxy) Dispatch(ctx context.Context, addr proxy.Address) (proxy.Address, error) {
	return w.Proxy.Dispatch(proxy.NewStore(ctx), addr)
}
