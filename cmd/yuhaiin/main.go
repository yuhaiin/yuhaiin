package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"
	"time"

	"net/http"
	_ "net/http/pprof"

	"github.com/Asutorufa/yuhaiin/internal/api"
	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/subscr"
	"google.golang.org/grpc"
)

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

func init() {
	log.SetFlags(log.Llongfile)

	go func() {
		// 开启pprof，监听请求
		err := http.ListenAndServe("0.0.0.0:6060", nil)
		if err != nil {
			fmt.Printf("start pprof failed on %s\n", "0.0.0.0:6060")
		}
	}()

	go func() {
		signChannel := make(chan os.Signal, 5)
		signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		for s := range signChannel {
			switch s {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				log.Println("kernel exit")
				os.Exit(0)
			default:
				fmt.Println("OTHERS SIGN:", s)
			}
		}
	}()
}

// protoc --go_out=plugins=grpc:. --go_opt=paths=source_relative api/api.proto
func main() {
	host := flag.String("host", "127.0.0.1:50051", "RPC SERVER HOST")
	configDir := flag.String("cd", defaultConfigDir(), "config dir")
	kwdc := flag.Bool("kwdc", false, "kill process when grpc disconnect")
	flag.Parse()

	go func() {
		if !*kwdc {
			return
		}

		ppid := os.Getppid()
		ticker := time.NewTicker(time.Second)

		for range ticker.C {
			if os.Getppid() == ppid {
				continue
			}

			log.Println("checked parent already exited, exit myself.")
			os.Exit(0)
		}
	}()

	fmt.Println("save config at:", *configDir)
	fmt.Println("gRPC Listen Host:", *host)

	conf, err := config.NewConfig(*configDir)
	if err != nil {
		panic(err)
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

	var nodeManager *subscr.NodeManager
	var flowStatis *app.ConnManager
	// initialize Local Servers Controller
	l, err := app.NewListener(conf, nil)
	if err != nil {
		log.Printf("create new listener failed: %v\n", err)
	} else {
		nodeManager, err = subscr.NewNodeManager(filepath.Join(*configDir, "node.json"))
		if err != nil {
			panic(err)
		}
		flowStatis = app.NewConnManager(app.NewBypassManager(conf, nodeManager))
		l.SetProxy(flowStatis)
	}

	lock := app.NewLock(filepath.Join(*configDir, "yuhaiin.lock"))
	defer lock.UnLock()

	lis, err := net.Listen("tcp", *host)
	if err != nil {
		panic(err)
	}
	s := grpc.NewServer(grpc.EmptyServerOption{})

	s.RegisterService(&api.Config_ServiceDesc, api.NewConfig(conf, flowStatis))  // TODO Deprecated
	s.RegisterService(&api.Node_ServiceDesc, api.NewNode(nodeManager))           // TODO Deprecated
	s.RegisterService(&api.Subscribe_ServiceDesc, api.NewSubscribe(nodeManager)) // TODO Deprecated

	s.RegisterService(&api.ProcessInit_ServiceDesc, api.NewProcess(lock, *host))
	s.RegisterService(&subscr.NodeManager_ServiceDesc, nodeManager)
	s.RegisterService(&config.ConfigDao_ServiceDesc, conf)
	s.RegisterService(&app.Connections_ServiceDesc, flowStatis)
	err = s.Serve(lis)
	if err != nil {
		panic(err)
	}
}
