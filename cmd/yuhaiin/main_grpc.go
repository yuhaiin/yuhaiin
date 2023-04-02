//go:build !lite
// +build !lite

package main

import (
	"google.golang.org/grpc"
)

func init() {
	newGrpcServer = func() *grpc.Server { return grpc.NewServer() }
}
