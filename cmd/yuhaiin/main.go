package main

import (
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/internal/config"
	simplehttp "github.com/Asutorufa/yuhaiin/internal/http"
	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	nodemanager "github.com/Asutorufa/yuhaiin/pkg/node"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
)

func listenSign(lis io.Closer) {
	signChannel := make(chan os.Signal, 1)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		<-signChannel
		if lis != nil {
			lis.Close()
		}
	}()
}

func initLog(configPath string) io.Closer {
	dir := filepath.Join(configPath, "log")
	_, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(dir, os.ModePerm)
	}
	out := []io.Writer{os.Stdout}
	f := logasfmt.NewLogWriter(filepath.Join(dir, "yuhaiin.log"))
	logasfmt.SetOutput(io.MultiWriter(append(out, f)...))

	return f
}

// protoc --go_out=plugins=grpc:. --go_opt=paths=source_relative api/api.proto
func main() {
	host := flag.String("host", "127.0.0.1:50051", "gRPC and http listen host")
	path := flag.String("path", protoconfig.DefaultConfigDir(), "save data path")
	flag.Parse()

	logger := initLog(*path)
	defer logger.Close()

	logasfmt.Println("\n\n\nsave config at:", *path)
	logasfmt.Println("gRPC and http listen at:", *host)

	lock, err := app.NewLock(filepath.Join(*path, "yuhaiin.lock"), *host)
	if err != nil {
		panic(err)
	}
	defer lock.UnLock()

	// initialize Local Servers Controller
	lis, err := net.Listen("tcp", *host)
	if err != nil {
		panic(err)
	}

	listenSign(lis)

	// * net.Conn/net.PacketConn -> nodeManger -> BypassManager&statis/connection manager -> listener
	nodes := nodemanager.NewNodeManager(filepath.Join(*path, "node.json"))
	setting := config.NewConfig(filepath.Join(*path, "config.json"))
	statistics := app.NewConnManager(setting, nodes)

	listener := app.NewListener(setting, statistics)
	defer listener.Close()

	sysproxy.Set(setting)
	defer sysproxy.Unset()

	mux := http.NewServeMux()
	simplehttp.Httpserver(mux, nodes, statistics, setting)

	grpcServer := grpc.NewServer()
	grpcServer.RegisterService(&node.NodeManager_ServiceDesc, nodes)
	grpcServer.RegisterService(&protoconfig.ConfigDao_ServiceDesc, setting)
	grpcServer.RegisterService(&statistic.Connections_ServiceDesc, statistics)

	// h2c for grpc insecure mode
	err = http.Serve(lis, h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			mux.ServeHTTP(w, r)
		}
	}), &http2.Server{}))
	if err != nil {
		panic(err)
	}
}
