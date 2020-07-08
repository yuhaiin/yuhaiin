//+build api

package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/api"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/grpc"
)

func TestApi(t *testing.T) {
	conn, err := grpc.Dial("127.0.0.1:50051", grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()
	c := api.NewApiClient(conn)
	log.Println(c.ProcessInit(context.Background(), &empty.Empty{}))
	log.Println(c.GetConfig(context.Background(), &empty.Empty{}))
	log.Println(c.GetGroup(context.Background(), &empty.Empty{}))
	log.Println(c.ReducedUnit(context.Background(), &wrappers.DoubleValue{Value: 11111111111111111}))
}

func TestPath(t *testing.T) {
	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		t.Error(err)
		return
	}
	path, err := filepath.Abs(file)
	if err != nil {
		t.Error(err)
		return
	}
	log.Println(filepath.Dir(path))
}
