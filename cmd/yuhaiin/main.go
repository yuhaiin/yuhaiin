package main

import (
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	"github.com/Asutorufa/yuhaiin/pkg/subscr"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"google.golang.org/grpc"
)

func initialize() {
	go func() {
		// pprof
		_ = http.ListenAndServe("0.0.0.0:6060", nil)
	}()

	go func() {
		signChannel := make(chan os.Signal, 5)
		signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

		// ppid := os.Getppid()
		// ticker := time.NewTicker(time.Second)

		for {
			select {
			case s := <-signChannel:
				switch s {
				case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
					log.Println("stop server")
					grpcServer.Stop()
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
		}
	}()
}

func initLog(configPath string) {
	dir := path.Join(configPath, "log")
	_, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(dir, os.ModePerm)
	}
	out := []io.Writer{os.Stdout}
	f := logasfmt.NewLogWriter(filepath.Join(dir, "yuhaiin.log"))
	defer f.Close()
	logasfmt.SetOutput(io.MultiWriter(append(out, f)...))
}

var grpcServer = grpc.NewServer(grpc.EmptyServerOption{})

// protoc --go_out=plugins=grpc:. --go_opt=paths=source_relative api/api.proto
func main() {
	host := flag.String("host", "127.0.0.1:50051", "RPC SERVER HOST")
	path := flag.String("cd", defaultConfigDir(), "config dir")
	flag.Parse()

	initLog(*path)

	logasfmt.Println(`
***************************************
***************************************
***********start yuhaiin***************
***************************************
***************************************`)
	logasfmt.Println("save config at:", *path)
	logasfmt.Println("gRPC Listen Host:", *host)

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

	initialize()

	// * net.Conn/net.PacketConn -> nodeManger -> BypassManager&statis/connection manager -> listener
	nodeManager, err := subscr.NewNodeManager(filepath.Join(*path, "node.json"))
	if err != nil {
		panic(err)
	}
	conf, err := config.NewConfig(*path)
	if err != nil {
		panic(err)
	}
	flowStatis, err := app.NewConnManager(conf, nodeManager)
	if err != nil {
		panic(err)
	}
	_ = app.NewListener(conf, flowStatis)

	sysproxy.Set(conf)
	defer sysproxy.Unset()

	grpcServer.RegisterService(&subscr.NodeManager_ServiceDesc, nodeManager)
	grpcServer.RegisterService(&config.ConfigDao_ServiceDesc, conf)
	grpcServer.RegisterService(&app.Connections_ServiceDesc, flowStatis)
	err = grpcServer.Serve(lis)
	if err != nil {
		panic(err)
	}
}

func defaultConfigDir() (Path string) {
	var err error
	Path, err = os.UserConfigDir()
	if err == nil {
		Path = path.Join(Path, "yuhaiin")
		return
	}

	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		log.Println(err)
		Path = "./yuhaiin"
		return
	}
	execPath, err := filepath.Abs(file)
	if err != nil {
		log.Println(err)
		Path = "./yuhaiin"
		return
	}
	Path = path.Join(filepath.Dir(execPath), "config")
	return
}
