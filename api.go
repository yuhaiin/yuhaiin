package main

import (
	"log"
	"net"

	//_ "net/http/pprof"

	"github.com/Asutorufa/yuhaiin/api"
	"google.golang.org/grpc"
)

// protoc --go_out=plugins=grpc:. --go_opt=paths=source_relative api/api.proto
func main() {
	log.SetFlags(log.Llongfile)

	//go func() {
	// 开启pprof，监听请求
	//	ip := "0.0.0.0:6060"
	//	if err := http.ListenAndServe(ip, nil); err != nil {
	//		fmt.Printf("start pprof failed on %s\n", ip)
	//	}
	//}()

	lis, err := net.Listen("tcp", api.Host)
	if err != nil {
		panic(err)
	}
	s := grpc.NewServer()
	api.RegisterProcessInitServer(s, &api.Process{})
	api.RegisterConfigServer(s, &api.Config{})
	api.RegisterNodeServer(s, &api.Node{})
	api.RegisterSubscribeServer(s, &api.Subscribe{})
	if err := s.Serve(lis); err != nil {
		log.Println(err)
	}
}
