package appapi

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/config"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	gt "github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"go.etcd.io/bbolt"
	"google.golang.org/grpc"
)

type Components struct {
	Mux *http.ServeMux
	*Start
	HttpListener net.Listener
	DB           *bbolt.DB

	Node           gn.NodeServer
	Tools          gt.ToolsServer
	Subscribe      gn.SubscribeServer
	Connections    gs.ConnectionsServer
	Inbound        gc.InboundServer
	Resolver       gc.ResolverServer
	RuleController gc.BypassServer
	Tag            gn.TagServer
}

func (app *Components) RegisterServer() {
	so := app.Start

	grpcServer := &grpcRegister{
		s:   app.Start.GRPCServer,
		app: app,
	}

	gc.RegisterConfigServiceServer(grpcServer, so.Setting)
	gc.RegisterBypassServer(grpcServer, app.RuleController)
	gc.RegisterInboundServer(grpcServer, app.Inbound)
	gc.RegisterResolverServer(grpcServer, app.Resolver)

	gn.RegisterNodeServer(grpcServer, app.Node)
	gn.RegisterSubscribeServer(grpcServer, app.Subscribe)
	gn.RegisterTagServer(grpcServer, app.Tag)

	gs.RegisterConnectionsServer(grpcServer, app.Connections)

	gt.RegisterToolsServer(grpcServer, app.Tools)

	RegisterHTTP(app)
}

type grpcRegister struct {
	app *Components
	s   *grpc.Server
}

func (g *grpcRegister) RegisterService(desc *grpc.ServiceDesc, impl any) {
	if g.s != nil { // when android, g.s is nil
		log.Info("register grpc service", "name", desc.ServiceName)
		g.s.RegisterService(desc, impl)
	}

	for _, method := range desc.Methods {
		path := fmt.Sprintf("POST /%s/%s", desc.ServiceName, method.MethodName)
		log.Info("register http handler", "path", path)

		HandleFunc(g.app, path, registerHTTP(impl, method.Handler))
	}

	for _, method := range desc.Streams {
		path := fmt.Sprintf("GET /%s/%s", desc.ServiceName, method.StreamName)
		log.Info("register websocket handler", "path", path)
		HandleFunc(g.app, path, registerWebsocket(impl, method.Handler))
	}
}

func (a *Components) Close() error {
	closers := slices.Clone(a.closers)
	slices.Reverse(closers)
	for _, v := range closers {
		v.Close()
	}

	log.Close()

	sysproxy.Unset()

	return nil
}

type Start struct {
	ConfigPath   string
	Host         string
	BypassConfig pc.DB
	Setting      config.Setting

	ProcessDumper netapi.ProcessDumper
	GRPCServer    *grpc.Server
	closers       []io.Closer
}

func (a *Start) AddCloser(name string, z io.Closer) {
	a.closers = append(a.closers, &moduleCloser{z, name})
}

type moduleCloser struct {
	io.Closer
	name string
}

func (m *moduleCloser) Close() error {
	log.Info("close", "module", m.name)
	defer log.Info("closed", "module", m.name)
	return m.Closer.Close()
}
