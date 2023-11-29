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

	web "github.com/Asutorufa/yuhaiin/internal/http"
	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/components/config"
	"github.com/Asutorufa/yuhaiin/pkg/components/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/components/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/components/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/components/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/components/tools"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	gt "github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"go.etcd.io/bbolt"
	"google.golang.org/grpc"
)

var App = app{Mux: http.NewServeMux()}

type app struct {
	Mux          *http.ServeMux
	so           *StartOpt
	HttpListener net.Listener
	Node         *node.Nodes
	Tools        *tools.Tools
	DB           *bbolt.DB
	closers      []io.Closer
}

type StartOpt struct {
	ConfigPath string
	Host       string
	Setting    config.Setting

	ProcessDumper listener.ProcessDumper
	GRPCServer    *grpc.Server
}

func AddComponent[T any](t T) T {
	if z, ok := any(t).(config.Observer); ok {
		App.so.Setting.AddObserver(z)
	}

	if z, ok := any(t).(io.Closer); ok {
		App.closers = append(App.closers, z)
	}

	return t
}

func AddCloser(z io.Closer) {
	App.closers = append(App.closers, z)
}

func Close() error {
	if i := len(App.closers) - 1; i >= 0 {
		App.closers[i].Close()
	}

	log.Close()

	var path string
	if App.so != nil {
		path = App.so.ConfigPath
	}
	sysproxy.Unset(path)

	App = app{Mux: http.NewServeMux()}

	return nil
}

func OpenBboltDB(path string) (*bbolt.DB, error) {
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

func Start(opt StartOpt) (err error) {
	App.so = &opt

	if App.DB == nil {
		App.DB, err = OpenBboltDB(PathGenerator.Cache(App.so.ConfigPath))
		if err != nil {
			return fmt.Errorf("init bbolt cache failed: %w", err)
		}
		AddCloser(App.DB)
	}

	App.HttpListener, err = net.Listen("tcp", App.so.Host)
	if err != nil {
		return err
	}
	AddCloser(App.HttpListener)

	App.so.Setting.AddObserver(config.ObserverFunc(func(s *pc.Setting) { log.Set(s.GetLogcat(), PathGenerator.Log(App.so.ConfigPath)) }))

	fmt.Println(version.Art)
	log.Info("config", "path", App.so.ConfigPath, "grpc&http host", App.so.Host)

	App.so.Setting.AddObserver(config.ObserverFunc(sysproxy.Update(App.so.ConfigPath)))
	App.so.Setting.AddObserver(config.ObserverFunc(func(s *pc.Setting) { dialer.DefaultInterfaceName = s.GetNetInterface() }))

	filestore := node.NewFileStore(PathGenerator.Node(App.so.ConfigPath))
	// proxy access point/endpoint
	App.Node = node.NewNodes(filestore)
	subscribe := node.NewSubscribe(filestore)
	tag := node.NewTag(filestore)

	// make dns flow across all proxy chain
	dynamicProxy := netapi.NewDynamicProxy(direct.Default)

	// wrap netapi.Store to context for every connection
	appDialer := netapi.NewWrapStoreProxy(dynamicProxy)

	// local,remote,bootstrap dns
	_ = AddComponent(resolver.NewBootstrap(appDialer))
	local := AddComponent(resolver.NewLocal(appDialer))
	remote := AddComponent(resolver.NewRemote(appDialer))
	// bypass dialer and dns request
	st := AddComponent(shunt.NewShunt(NewShuntOpt(local, remote)))
	App.Node.SetRuleTags(st.Tags)
	// connections' statistic & flow data
	stcs := AddComponent(statistics.NewConnStore(cache.NewCache(App.DB, "flow_data"), st, App.so.ProcessDumper))
	hosts := AddComponent(resolver.NewHosts(stcs, st))
	// wrap dialer and dns resolver to fake ip, if use
	fakedns := AddComponent(resolver.NewFakeDNS(hosts, hosts, cache.NewCache(App.DB, "fakedns_cache")))
	// dns server/tun dns hijacking handler
	dnsServer := AddComponent(resolver.NewDNSServer(fakedns))
	// make dns flow across all proxy chain
	dynamicProxy.Set(fakedns)
	ss := AddComponent(inbound.NewHandler(fakedns, dnsServer))
	// inbound server
	_ = AddComponent(inbound.NewListener(dnsServer, ss))
	// tools
	App.Tools = tools.NewTools(fakedns, opt.Setting)
	// http page
	web.Httpserver(NewHttpOption(subscribe, stcs, tag, st))
	// grpc server
	RegisterGrpcService(subscribe, stcs, tag)

	return nil
}

func RegisterGrpcService(sub gn.SubscribeServer, conns gs.ConnectionsServer, tag gn.TagServer) {
	if App.so.GRPCServer == nil {
		return
	}

	App.so.GRPCServer.RegisterService(&gc.ConfigService_ServiceDesc, App.so.Setting)
	App.so.GRPCServer.RegisterService(&gn.Node_ServiceDesc, App.Node)
	App.so.GRPCServer.RegisterService(&gn.Subscribe_ServiceDesc, sub)
	App.so.GRPCServer.RegisterService(&gs.Connections_ServiceDesc, conns)
	App.so.GRPCServer.RegisterService(&gn.Tag_ServiceDesc, tag)
	App.so.GRPCServer.RegisterService(&gt.Tools_ServiceDesc, App.Tools)
}

func NewShuntOpt(local, remote netapi.Resolver) shunt.Opts {
	return shunt.Opts{
		DirectDialer:   direct.Default,
		DirectResolver: local,
		ProxyDialer:    App.Node,
		ProxyResolver:  remote,
		BlockDialer:    reject.Default,
		BLockResolver:  netapi.ErrorResolver(func(domain string) error { return netapi.NewBlockError(-2, domain) }),
		DefaultMode:    bypass.Mode_proxy,
	}
}

func NewHttpOption(sub gn.SubscribeServer, conns gs.ConnectionsServer, tag gn.TagServer, st *shunt.Shunt) web.HttpServerOption {
	return web.HttpServerOption{
		Mux:         App.Mux,
		NodeServer:  App.Node,
		Subscribe:   sub,
		Connections: conns,
		Config:      App.so.Setting,
		Tag:         tag,
		Shunt:       st,
		Tools:       App.Tools,
	}
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
