//+build api

package main

import (
	"flag"
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/api"
	"google.golang.org/grpc"
)

var (
	host string
)

// protoc --go_out=plugins=grpc:. --go_opt=paths=source_relative api/api.proto
func main() {
	flag.StringVar(&host, "host", "127.0.0.1:50051", "RPC SERVER HOST")
	flag.Parse()
	log.Println(host)
	lis, err := net.Listen("tcp", host)
	if err != nil {
		log.Fatalf("%v", err)
	}
	s := grpc.NewServer()
	api.RegisterApiServer(s, &api.Server{})
	if err := s.Serve(lis); err != nil {
		log.Println(err)
	}
}
