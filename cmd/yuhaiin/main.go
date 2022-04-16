package main

import (
	"errors"
	"flag"
	"io"
	"log"
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

func initialize() {
	go func() {
		signChannel := make(chan os.Signal, 5)
		signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

		// ppid := os.Getppid()
		// ticker := time.NewTicker(time.Second)

		for s := range signChannel {
			switch s {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				log.Println("stop server")
				if lis != nil {
					lis.Close()
				}
				return
			default:
				logasfmt.Println("OTHERS SIGN:", s)
			}

			// case <-ticker.C:
			// 	if os.Getppid() == ppid {
			// 		continue
			// 	}

			// 	log.Println("checked parent already exited, exit myself.")
			// 	grpcServer.Stop()
			// 	return
		}
	}()
}

func initLog(configPath string) (close func() error) {
	dir := filepath.Join(configPath, "log")
	_, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(dir, os.ModePerm)
	}
	out := []io.Writer{os.Stdout}
	f := logasfmt.NewLogWriter(filepath.Join(dir, "yuhaiin.log"))
	logasfmt.SetOutput(io.MultiWriter(append(out, f)...))

	return f.Close
}

// var grpcServer = grpc.NewServer(grpc.EmptyServerOption{})
var lis net.Listener

// protoc --go_out=plugins=grpc:. --go_opt=paths=source_relative api/api.proto
func main() {
	host := flag.String("host", "127.0.0.1:50051", "RPC SERVER HOST")
	path := flag.String("cd", protoconfig.DefaultConfigDir(), "config dir")
	flag.Parse()

	close := initLog(*path)
	defer close()

	logasfmt.Println("\n\n\nsave config at:", *path)
	logasfmt.Println("gRPC&HTTP Listen Host:", *host)

	lock, err := app.NewLock(filepath.Join(*path, "yuhaiin.lock"), *host)
	if err != nil {
		panic(err)
	}
	defer lock.UnLock()

	// initialize Local Servers Controller
	lis, err = net.Listen("tcp", *host)
	if err != nil {
		panic(err)
	}

	initialize()

	// * net.Conn/net.PacketConn -> nodeManger -> BypassManager&statis/connection manager -> listener
	nodeManager := nodemanager.NewNodeManager(filepath.Join(*path, "node.json"))
	conf := config.NewConfig(*path)
	flowStatis := app.NewConnManager(conf, nodeManager)
	_ = app.NewListener(conf, flowStatis)

	sysproxy.Set(conf)
	defer sysproxy.Unset()

	mux := http.NewServeMux()
	simplehttp.Httpserver(mux, nodeManager, flowStatis, conf)

	grpcServer := grpc.NewServer()
	grpcServer.RegisterService(&node.NodeManager_ServiceDesc, nodeManager)
	grpcServer.RegisterService(&protoconfig.ConfigDao_ServiceDesc, conf)
	grpcServer.RegisterService(&statistic.Connections_ServiceDesc, flowStatis)

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
