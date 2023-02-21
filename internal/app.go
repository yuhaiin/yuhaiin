package yuhaiin

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/config"
	web "github.com/Asutorufa/yuhaiin/internal/http"
	"github.com/Asutorufa/yuhaiin/internal/inbound"
	"github.com/Asutorufa/yuhaiin/internal/resolver"
	"github.com/Asutorufa/yuhaiin/internal/shunt"
	"github.com/Asutorufa/yuhaiin/internal/statistics"
	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	is "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
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

func (s *StartOpt) addObserver(observer any) {
	if z, ok := observer.(config.Observer); ok {
		s.Setting.AddObserver(z)
	}
}

type StartResponse struct {
	HttpListener net.Listener

	Mux *http.ServeMux

	Node *node.Nodes

	servers []is.Server
}

func (s *StartResponse) Close() error {
	for _, z := range s.servers {
		z.Close()
	}
	log.Close()
	sysproxy.Unset()
	return nil
}

func initBboltDB(path string) *bbolt.DB {
	db, err := bbolt.Open(path, os.ModePerm, &bbolt.Options{Timeout: time.Second})
	switch err {
	case bbolt.ErrInvalid, bbolt.ErrChecksum, bbolt.ErrVersionMismatch:
		if err = os.Remove(path); err != nil {
			break
		}
		log.Infoln("[CacheFile] remove invalid cache file and create new one")
		db, err = bbolt.Open(path, os.ModePerm, &bbolt.Options{Timeout: time.Second})
	}
	if err != nil {
		log.Warningln("can't open cache file:", err)
	}

	return db
}

func Start(opt StartOpt) (StartResponse, error) {
	db := initBboltDB(PathGenerator.Cache(opt.ConfigPath))

	lis, err := net.Listen("tcp", opt.Host)
	if err != nil {
		return StartResponse{}, err
	}

	log.Infof("%s\nConfig Path: %s\ngRPC&HTTP Listen At: %s\n", version.Art, opt.ConfigPath, opt.Host)

	opt.Setting.AddObserver(config.ObserverFunc(sysproxy.Update))
	opt.Setting.AddObserver(config.ObserverFunc(func(s *pc.Setting) { log.Set(s.GetLogcat(), PathGenerator.Log(opt.ConfigPath)) }))
	opt.Setting.AddObserver(config.ObserverFunc(func(s *pc.Setting) { dialer.DefaultInterfaceName = s.GetNetInterface() }))

	filestore := node.NewFileStore(PathGenerator.Node(opt.ConfigPath))
	// proxy access point/endpoint
	nodeService := node.NewNodes(filestore)
	subscribe := node.NewSubscribe(filestore)
	tag := node.NewTag(filestore)

	// make dns flow across all proxy chain
	appDialer := &struct{ proxy.Proxy }{}

	// local,remote,bootstrap dns
	resolvers := resolver.NewResolvers(appDialer)
	opt.addObserver(resolvers)

	// bypass dialer and dns request
	st := shunt.NewShunt([]shunt.Mode{
		{
			Mode:     bypass.Mode_proxy,
			Default:  true,
			Dialer:   nodeService,
			Resolver: resolvers.Remote,
		},
		{
			Mode:     bypass.Mode_direct,
			Default:  false,
			Dialer:   direct.Default,
			Resolver: resolvers.Local,
		},
		{
			Mode:     bypass.Mode_block,
			Default:  false,
			Dialer:   reject.Default,
			Resolver: dns.NewErrorDNS(func(domain string) error { return proxy.NewBlockError(-2, domain) }),
		},
	})
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
	appDialer.Proxy = stcs

	// http/socks5/redir/tun server
	listener := inbound.NewListener(
		&listener.Opts[listener.IsProtocol_Protocol]{
			Dialer:    fakedns,
			DNSServer: dnsServer,
		},
	)
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
		servers:      []is.Server{stcs, listener, resolvers, dnsServer, db},
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

/*
      dial ip
        ^
        |
+------------------+  +----------------------+
|proxy/direct/block|->|local/remote/bootstrap|---------------+
+------------------+  +----------------------+               |
         ^                          ^                        |
         |                          |                        |
         +-----+        +-----------+                        |
               |        |                                    |
	       |        |                                    |
         +-----------------+                                 |
         |      shunt      |                                 |
	 +-----------------+                                 |
		  ^                                          |
		  |                                          |
	 +-----------------+                                 |
	 |   fake  dns     |                                 |
	 +-----------------+                                 |
		^  ^                                         |
                |  |                                         |
         +------+  +-------+                                 |
	 |                 |                                 |
         |                 |                                 |
+------------+   +--------------+                            |
| dnsserver  |   |  statistic   |<---------------------------+
+------------+   +--------------+
	  ^		^
	  |<-----+	|
	  | 	 |   +--------------+
	request	 +---|  listeners   |
		     +--------------+
			  ^
			  |
			  |
			  |
			request

*/
