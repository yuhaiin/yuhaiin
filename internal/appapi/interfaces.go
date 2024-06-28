package appapi

import (
	"io"
	"net"
	"net/http"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/config"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/node"
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
	Node         *node.Nodes
	Tools        *gt.Tools
	Subscribe    gn.SubscribeServer
	Connections  gs.ConnectionsServer
	Tag          gn.TagServer
	DB           *bbolt.DB
}

func (app *Components) RegisterGrpcService() {
	so := app.Start
	if so.GRPCServer == nil {
		return
	}

	so.GRPCServer.RegisterService(&gc.ConfigService_ServiceDesc, so.Setting)
	so.GRPCServer.RegisterService(&gn.Node_ServiceDesc, app.Node)
	so.GRPCServer.RegisterService(&gn.Subscribe_ServiceDesc, app.Subscribe)
	so.GRPCServer.RegisterService(&gs.Connections_ServiceDesc, app.Connections)
	so.GRPCServer.RegisterService(&gn.Tag_ServiceDesc, app.Tag)
	so.GRPCServer.RegisterService(&gt.Tools_ServiceDesc, app.Tools)
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
	ConfigPath string
	Host       string
	Setting    config.Setting

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
