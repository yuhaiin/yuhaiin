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

	"github.com/Asutorufa/yuhaiin/internal/api"
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
	f, err := os.OpenFile(filepath.Join(dir, "yuhaiin.log"), os.O_APPEND|os.O_CREATE|os.O_RDWR, os.ModePerm)
	if err == nil {
		defer f.Close()
		out = append(out, f)
	}
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

	/*
	* net.Conn/net.PacketConn
	*    |
	* nodeManger
	*    |
	* BypassManager
	*    |
	* statis/connection manager
	*    |
	* listener
	 */

	nodeManager, err := subscr.NewNodeManager(filepath.Join(*configDir, "node.json"))
	if err != nil {
		panic(err)
	}

	conf, err := config.NewConfig(*configDir)
	if err != nil {
		panic(err)
	}

	flowStatis := app.NewConnManager(app.NewBypassManager(conf, nodeManager))

	_, err = app.NewListener(conf, flowStatis)
	if err != nil {
		log.Printf("create new listener failed: %v\n", err)
	}

	runSetSysProxy(conf)
	defer sysproxy.UnsetSysProxy()

	grpcServer.RegisterService(&api.Config_ServiceDesc, api.NewConfig(conf, flowStatis))  // TODO Deprecated
	grpcServer.RegisterService(&api.Node_ServiceDesc, api.NewNode(nodeManager))           // TODO Deprecated
	grpcServer.RegisterService(&api.Subscribe_ServiceDesc, api.NewSubscribe(nodeManager)) // TODO Deprecated
	grpcServer.RegisterService(&api.ProcessInit_ServiceDesc, api.NewProcess(lock, *host))
	grpcServer.RegisterService(&subscr.NodeManager_ServiceDesc, nodeManager)
	grpcServer.RegisterService(&config.ConfigDao_ServiceDesc, conf)
	grpcServer.RegisterService(&app.Connections_ServiceDesc, flowStatis)
	err = grpcServer.Serve(lis)
	if err != nil {
		panic(err)
	}
}

func runSetSysProxy(conf *config.Config) {
	setSysProxy := func(s *config.Setting) {
		var http, socks5 string
		if s.SystemProxy.HTTP {
			http = s.Proxy.HTTP
		}
		if s.SystemProxy.Socks5 {
			socks5 = s.Proxy.Socks5
		}
		sysproxy.SetSysProxy(http, socks5)
	}

	conf.Exec(func(s *config.Setting) error {
		setSysProxy(s)
		return nil
	})
	conf.AddObserver(func(current, old *config.Setting) {
		if current.SystemProxy.HTTP != old.SystemProxy.HTTP ||
			current.SystemProxy.HTTP != old.SystemProxy.Socks5 ||
			current.Proxy.HTTP != old.Proxy.HTTP ||
			current.Proxy.Socks5 != old.Proxy.Socks5 {
			sysproxy.UnsetSysProxy()
			setSysProxy(current)
		}
	})
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
