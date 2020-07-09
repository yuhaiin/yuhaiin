//+build api

package main

import (
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/api"
	"google.golang.org/grpc"
)

// protoc --go_out=plugins=grpc:. --go_opt=paths=source_relative api/api.proto
func main() {
	log.SetFlags(log.Llongfile)

	lis, err := net.Listen("tcp", api.Host)
	if err != nil {
		panic(err)
	}
	s := grpc.NewServer()
	api.RegisterApiServer(s, &api.Server{})
	if err := s.Serve(lis); err != nil {
		log.Println(err)
	}
}
