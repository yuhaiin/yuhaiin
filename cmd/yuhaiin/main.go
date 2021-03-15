package main

import (
	"fmt"
	"log"
	"net"
	"net/http"

	_ "net/http/pprof"

	"github.com/Asutorufa/yuhaiin/internal/api"
	"github.com/Asutorufa/yuhaiin/internal/app"
	"google.golang.org/grpc"
)

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

	m, err := app.NewManager()
	if err != nil {
		panic(err)
	}
	err = m.Start()
	if err != nil {
		panic(err)
	}

	lis, err := net.Listen("tcp", m.Host())
	if err != nil {
		panic(err)
	}

	s := grpc.NewServer(grpc.EmptyServerOption{})
	s.RegisterService(&api.ProcessInit_ServiceDesc, api.NewProcess(m))
	s.RegisterService(&api.Config_ServiceDesc, api.NewConfig(m.Entrance()))
	s.RegisterService(&api.Node_ServiceDesc, api.NewNode(m.Entrance()))
	s.RegisterService(&api.Subscribe_ServiceDesc, api.NewSubscribe(m.Entrance()))
	err = s.Serve(lis)
	if err != nil {
		panic(err)
	}
}
