package yuhaiin

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/internal/hosts"
	simplehttp "github.com/Asutorufa/yuhaiin/internal/http"
	"github.com/Asutorufa/yuhaiin/internal/resolver"
	"github.com/Asutorufa/yuhaiin/internal/server"
	"github.com/Asutorufa/yuhaiin/internal/shunt"
	"github.com/Asutorufa/yuhaiin/internal/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	grpcconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	grpcsts "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"google.golang.org/grpc"
)

const yuhaiinArt = `
_____.___.     .__           .__.__        
\__  |   |__ __|  |__ _____  |__|__| ____  
 /   |   |  |  \  |  \\__  \ |  |  |/    \ 
 \____   |  |  /   Y  \/ __ \|  |  |   |  \
 / ______|____/|___|  (____  /__|__|___|  /
 \/                 \/     \/           \/ 
Config Path: %s
gRPC&HTTP Listen At: %s`

type StartOpt struct {
	PathConfig struct{ Dir, Lockfile, Node, Config, Logfile string }
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

	servers []iserver.Server
}

func (s *StartResponse) Close() error {
	for _, z := range s.servers {
		z.Close()
	}
	log.Close()
	return nil
}

func Start(opt StartOpt) (StartResponse, error) {
	lis, err := net.Listen("tcp", opt.Host)
	if err != nil {
		return StartResponse{}, err
	}

	log.Infof(yuhaiinArt, opt.PathConfig.Dir, opt.Host)

	opt.Setting.AddObserver(config.ObserverFunc(sysproxy.Update))
	defer sysproxy.Unset()
	opt.Setting.AddObserver(config.ObserverFunc(func(s *protoconfig.Setting) { log.Set(s.GetLogcat(), opt.PathConfig.Logfile) }))
	opt.Setting.AddObserver(config.ObserverFunc(func(s *protoconfig.Setting) { dialer.DefaultInterfaceName = s.GetNetInterface() }))

	filestore := node.NewFileStore(opt.PathConfig.Node)
	// proxy access point/endpoint
	nodeService := node.NewNodes(filestore)
	subscribe := node.NewSubscribe(filestore)

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
			Resolver: resolvers.Remote(),
		},
		{
			Mode:     bypass.Mode_direct,
			Default:  false,
			Dialer:   direct.Default,
			Resolver: resolvers.Local(),
		},
		{
			Mode:     bypass.Mode_block,
			Default:  false,
			Dialer:   reject.NewReject(5, 15),
			Resolver: dns.NewErrorDNS(errors.New("block")),
		},
	})
	opt.addObserver(st)

	// connections' statistic & flow data
	stcs := statistics.NewConnStore(st, opt.ProcessDumper)

	hosts := hosts.NewHosts(stcs, st)
	opt.addObserver(hosts)

	// wrap dialer and dns resolver to fake ip, if use
	fakedns := resolver.NewFakeDNS(hosts, hosts)
	opt.addObserver(fakedns)

	// dns server/tun dns hijacking handler
	dnsServer := resolver.NewDNSServer(fakedns)
	opt.addObserver(dnsServer)

	// give dns a dialer
	appDialer.Proxy = stcs

	// http/socks5/redir/tun server
	listener := server.NewListener(
		&listener.Opts[listener.IsProtocol_Protocol]{
			Dialer:    fakedns,
			DNSServer: dnsServer,
		},
	)
	opt.addObserver(listener)

	// http page
	mux := http.NewServeMux()
	simplehttp.Httpserver(mux, nodeService, subscribe, stcs, opt.Setting)

	// grpc server
	if opt.GRPCServer != nil {
		opt.GRPCServer.RegisterService(&grpcconfig.ConfigDao_ServiceDesc, opt.Setting)
		opt.GRPCServer.RegisterService(&grpcnode.Node_ServiceDesc, nodeService)
		opt.GRPCServer.RegisterService(&grpcnode.Subscribe_ServiceDesc, subscribe)
		opt.GRPCServer.RegisterService(&grpcsts.Connections_ServiceDesc, stcs)
	}

	return StartResponse{
		HttpListener: lis,
		Mux:          mux,
		Node:         nodeService,
		servers:      []iserver.Server{stcs, listener, resolvers, dnsServer},
	}, nil
}

func PathConfig(configPath string) struct{ Dir, Lockfile, Node, Config, Logfile string } {
	create := func(child ...string) string { return filepath.Join(append([]string{configPath}, child...)...) }
	config := struct{ Dir, Lockfile, Node, Config, Logfile string }{
		configPath, create("LOCK"),
		create("node.json"), create("config.json"),
		create("log", "yuhaiin.log"),
	}

	if _, err := os.Stat(config.Logfile); errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(filepath.Dir(config.Logfile), os.ModePerm)
	}

	return config
}

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
