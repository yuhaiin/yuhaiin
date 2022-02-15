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
	"time"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	"github.com/Asutorufa/yuhaiin/pkg/subscr"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"google.golang.org/grpc"
)

func init() {
	go func() {
		// pprof
		_ = http.ListenAndServe("0.0.0.0:6060", nil)
	}()

	go func() {
		signChannel := make(chan os.Signal, 5)
		signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		for s := range signChannel {
			switch s {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				log.Println("stop server")
				grpcServer.Stop()
			default:
				logasfmt.Println("OTHERS SIGN:", s)
			}
		}
	}()
}

var grpcServer = grpc.NewServer(grpc.EmptyServerOption{})

// protoc --go_out=plugins=grpc:. --go_opt=paths=source_relative api/api.proto
func main() {
	host := flag.String("host", "127.0.0.1:50051", "RPC SERVER HOST")
	configDir := flag.String("cd", defaultConfigDir(), "config dir")
	kwdc := flag.Bool("kwdc", false, "kill process when grpc disconnect")
	flag.Parse()

	dir := path.Join(*configDir, "log")
	_, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(dir, os.ModePerm)
	}

	out := []io.Writer{os.Stdout}
	f := logasfmt.NewLogWriter(filepath.Join(dir, "yuhaiin.log"))
	defer f.Close()
	out = append(out, f)
	logasfmt.SetOutput(io.MultiWriter(out...))
	logasfmt.Println("--------start yuhaiin----------")
	logasfmt.Println("save config at:", *configDir)
	logasfmt.Println("gRPC Listen Host:", *host)

	lock, err := app.NewLock(filepath.Join(*configDir, "yuhaiin.lock"), *host)
	if err != nil {
		panic(err)
	}
	defer lock.UnLock()

	// initialize Local Servers Controller
	lis, err := net.Listen("tcp", *host)
	if err != nil {
		panic(err)
	}

	if !*kwdc {
		stopWithParentExited()
	}

	// * net.Conn/net.PacketConn -> nodeManger -> BypassManager -> statis/connection manager -> listener
	nodeManager, err := subscr.NewNodeManager(filepath.Join(*configDir, "node.json"))
	if err != nil {
		panic(err)
	}
	conf, err := config.NewConfig(*configDir)
	if err != nil {
		panic(err)
	}
	flowStatis := app.NewConnManager(app.NewBypassManager(conf, nodeManager))
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

func stopWithParentExited() {
	go func() {
		ppid := os.Getppid()
		ticker := time.NewTicker(time.Second)

		for range ticker.C {
			if os.Getppid() == ppid {
				continue
			}

			log.Println("checked parent already exited, exit myself.")
			grpcServer.Stop()
		}
	}()
}
