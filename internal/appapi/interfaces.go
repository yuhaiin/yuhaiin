package appapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pt "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	gt "github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"go.etcd.io/bbolt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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
	Setting        gc.ConfigServiceServer
}

func (app *Components) RegisterServer() {
	grpcServer := &grpcRegister{
		s:    app.Start.GRPCServer,
		mux:  app.Mux,
		auth: app.Auth,
	}

	gc.RegisterConfigServiceServer(grpcServer, app.Setting)
	gc.RegisterBypassServer(grpcServer, app.RuleController)
	gc.RegisterInboundServer(grpcServer, app.Inbound)
	gc.RegisterResolverServer(grpcServer, app.Resolver)

	gn.RegisterNodeServer(grpcServer, app.Node)
	gn.RegisterSubscribeServer(grpcServer, app.Subscribe)
	gn.RegisterTagServer(grpcServer, app.Tag)

	gs.RegisterConnectionsServer(grpcServer, app.Connections)

	gt.RegisterToolsServer(grpcServer, app.Tools)

	RegisterHTTP(app.Mux)
}

type grpcRegister struct {
	mux  *http.ServeMux
	s    *grpc.Server
	auth *Auth
}

func (g *grpcRegister) RegisterService(desc *grpc.ServiceDesc, impl any) {
	if g.s != nil { // when android, g.s is nil
		log.Info("register grpc service", "name", desc.ServiceName)
		g.s.RegisterService(desc, impl)
	}

	for _, method := range desc.Methods {
		path := fmt.Sprintf("POST /%s/%s", desc.ServiceName, method.MethodName)
		log.Info("register http handler", "path", path)
		HandleFunc(g.mux, g.auth, path, registerHTTP(impl, method.Handler))
	}

	for _, method := range desc.Streams {
		path := fmt.Sprintf("GET /%s/%s", desc.ServiceName, method.StreamName)
		log.Info("register websocket handler", "path", path)
		HandleFunc(g.mux, g.auth, path, registerWebsocket(impl, method.Handler))
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
	ConfigPath     string
	Host           string
	Auth           *Auth
	BypassConfig   pc.DB
	ResolverConfig pc.DB
	InboundConfig  pc.DB
	ChoreConfig    pc.DB

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

type Auth struct {
	Username [32]byte
	Password [32]byte
}

func NewAuth(username, password string) *Auth {
	return &Auth{
		Username: sha256.Sum256([]byte(username)),
		Password: sha256.Sum256([]byte(password)),
	}
}

func (a *Auth) Auth(password, username string) bool {
	rSumUser := sha256.Sum256([]byte(username))
	rSumPass := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(rSumUser[:], a.Username[:]) == 1 && subtle.ConstantTimeCompare(rSumPass[:], a.Password[:]) == 1
}

func (a *Auth) GrpcAuth() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "metadata not found")
		}

		as := md.Get("Authorization")
		if len(as) == 0 {
			return nil, status.Error(codes.Unauthenticated, "authorization header not found")
		}

		ru, rp, ok := pt.ParseBasicAuth(as[0])
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "authorization failed")
		}

		if !a.Auth(ru, rp) {
			return nil, status.Error(codes.Unauthenticated, "authorization failed")
		}

		return handler(ctx, req)
	}
}
