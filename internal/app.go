package yuhaiin

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/internal/config"
	simplehttp "github.com/Asutorufa/yuhaiin/internal/http"
	"github.com/Asutorufa/yuhaiin/internal/router"
	"github.com/Asutorufa/yuhaiin/internal/server"
	"github.com/Asutorufa/yuhaiin/internal/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	grpcconfig "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/config"
	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/node"
	grpcsts "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/statistic"
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
	Rules      map[protoconfig.BypassMode]string `json:"rules"`

	UidDumper  protoconfig.UidDumper
	GRPCServer *grpc.Server
}

type StartResponse struct {
	HttpListener net.Listener

	Mux *http.ServeMux

	Node       *node.Nodes
	Statistics statistics.Statistics
	listeners  iserver.Server
	Resolvers  *router.Resolvers
	Router     *router.Router
}

func (s *StartResponse) Close() error {
	s.Router.Close()
	s.Resolvers.Close()
	s.listeners.Close()
	s.Statistics.Close()
	log.Close()
	return nil
}

func Start(opt StartOpt) (StartResponse, error) {
	lis, err := net.Listen("tcp", opt.Host)
	if err != nil {
		return StartResponse{}, err
	}

	log.Infof(yuhaiinArt, opt.PathConfig.Dir, opt.Host)

	opt.Setting.AddObserver(config.NewObserver(func(s *protoconfig.Setting) { log.Set(s.GetLogcat(), opt.PathConfig.Logfile) }))
	opt.Setting.AddObserver(config.NewObserver(func(s *protoconfig.Setting) { dialer.DefaultInterfaceName = s.GetNetInterface() }))

	node := node.NewNodes(opt.PathConfig.Node)

	stcs := statistics.NewStatistics()

	resolvers := router.NewResolvers(direct.Default, node, stcs)
	opt.Setting.AddObserver(resolvers)

	route := router.NewRouter(stcs, resolvers.Remote(),
		[]router.Mode{
			{
				Mode:     protoconfig.Bypass_proxy,
				Default:  true,
				Dialer:   node,
				Resolver: resolvers.Remote(),
				Rules:    opt.Rules[protoconfig.Bypass_proxy],
			},
			{
				Mode:     protoconfig.Bypass_direct,
				Default:  false,
				Dialer:   direct.Default,
				Resolver: resolvers.Local(),
				Rules:    opt.Rules[protoconfig.Bypass_direct],
			},
			{
				Mode:     protoconfig.Bypass_block,
				Default:  false,
				Dialer:   reject.NewReject(5, 15),
				Resolver: dns.NewErrorDNS(errors.New("block")),
				Rules:    opt.Rules[protoconfig.Bypass_block],
			},
		})
	opt.Setting.AddObserver(route)

	listener := server.NewListener(
		&protoconfig.Opts[protoconfig.IsServerProtocol_Protocol]{Dialer: route, DNSServer: route, UidDumper: opt.UidDumper},
	)
	opt.Setting.AddObserver(listener)

	mux := http.NewServeMux()
	simplehttp.Httpserver(mux, node, stcs, opt.Setting)

	if opt.GRPCServer != nil {
		opt.GRPCServer.RegisterService(&grpcconfig.ConfigDao_ServiceDesc, opt.Setting)
		opt.GRPCServer.RegisterService(&grpcnode.NodeManager_ServiceDesc, node)
		opt.GRPCServer.RegisterService(&grpcsts.Connections_ServiceDesc, stcs)
	}

	return StartResponse{
		HttpListener: lis,
		Mux:          mux,
		Node:         node,
		Statistics:   stcs,
		listeners:    listener,
		Resolvers:    resolvers,
		Router:       route,
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
