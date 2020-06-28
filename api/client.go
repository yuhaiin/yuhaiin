package api

import (
	"log"

	grpc "google.golang.org/grpc"
)

func NewClient(host string) ApiClient {
	conn, err := grpc.Dial(host, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Println(err)
	}
	//defer conn.Close()
	c := NewApiClient(conn)
	return c
}
