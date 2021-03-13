package main

import (
	"fmt"
	"log"
	"net"
	"net/http"

	_ "net/http/pprof"

	"github.com/Asutorufa/yuhaiin/api"
	"github.com/Asutorufa/yuhaiin/app"
	"google.golang.org/grpc"
)

// protoc --go_out=plugins=grpc:. --go_opt=paths=source_relative api/api.proto
func main() {
	log.SetFlags(log.Llongfile)

	go func() {
		// 开启pprof，监听请求
		ip := "0.0.0.0:6060"
		if err := http.ListenAndServe(ip, nil); err != nil {
			fmt.Printf("start pprof failed on %s\n", ip)
		}
	}()

	s := grpc.NewServer()

	e, err := app.NewEntrance()
	if err != nil {
		panic(err)
	}
	p, err := api.NewProcess(e)
	if err != nil {
		panic(err)
	}
	api.RegisterProcessInitServer(s, p)
	config := api.NewConfig(e)
	api.RegisterConfigServer(s, config)
	node := api.NewNode(e)
	api.RegisterNodeServer(s, node)
	sub := api.NewSubscribe(e)
	api.RegisterSubscribeServer(s, sub)

	lis, err := net.Listen("tcp", p.Host())
	if err != nil {
		panic(err)
	}
	if err := s.Serve(lis); err != nil {
		log.Println(err)
	}
}
