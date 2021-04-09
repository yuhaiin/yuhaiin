package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	_ "net/http/pprof"

	"github.com/Asutorufa/yuhaiin/internal/api"
	"github.com/Asutorufa/yuhaiin/internal/app"
	"google.golang.org/grpc"
)

var (
	Path string
)

func init() {
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
}

// protoc --go_out=plugins=grpc:. --go_opt=paths=source_relative api/api.proto
func main() {
	log.SetFlags(log.Llongfile)

	go func() {
		// 开启pprof，监听请求
		err := http.ListenAndServe("0.0.0.0:6060", nil)
		if err != nil {
			fmt.Printf("start pprof failed on %s\n", "0.0.0.0:6060")
		}
	}()

	var host string
	var kwdc bool
	flag.StringVar(&host, "host", "127.0.0.1:50051", "RPC SERVER HOST")
	flag.BoolVar(&kwdc, "kwdc", false, "kill process when grpc disconnect")
	flag.Parse()
	fmt.Println("gRPC Listen Host :", host)
	fmt.Println("Try to create lock file.")

	m, err := app.NewManager(Path)
	if err != nil {
		panic(err)
	}

	err = m.Start(host)
	if err != nil {
		panic(err)
	}

	lis, err := net.Listen("tcp", host)
	if err != nil {
		panic(err)
	}

	s := grpc.NewServer(grpc.EmptyServerOption{})
	s.RegisterService(&api.ProcessInit_ServiceDesc, api.NewProcess(m, kwdc))
	s.RegisterService(&api.Config_ServiceDesc, api.NewConfig(m.Entrance()))
	s.RegisterService(&api.Node_ServiceDesc, api.NewNode(m.Entrance()))
	s.RegisterService(&api.Subscribe_ServiceDesc, api.NewSubscribe(m.Entrance()))
	err = s.Serve(lis)
	if err != nil {
		panic(err)
	}
}
