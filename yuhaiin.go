// +build !api

package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/api"
	"github.com/Asutorufa/yuhaiin/process/controller"
	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"

	//_ "net/http/pprof"

	"github.com/Asutorufa/yuhaiin/gui"
)

func main() {
	//go func() {
	//	// 开启pprof，监听请求
	//	ip := "0.0.0.0:6060"
	//	if err := http.ListenAndServe(ip, nil); err != nil {
	//		fmt.Printf("start pprof failed on %s\n", ip)
	//	}
	//}()

	var extKernel bool
	flag.BoolVar(&extKernel, "nokernel", false, "not run kernel")
	var clientHost string
	flag.StringVar(&clientHost, "host", "127.0.0.1:50051", "kernel rpc host")

	log.SetFlags(log.Lshortfile | log.LstdFlags)
	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		log.Println(err)
		return
	}
	path, err := filepath.Abs(file)
	if err != nil {
		log.Println(err)
		return
	}
	var kernel string
	flag.StringVar(&kernel, "kernel", filepath.Dir(path)+"/kernel", "kernel file")
	flag.Parse()

	if !extKernel {
		port, err := controller.GetFreePort()
		if err != nil {
			gui.MessageBox(err.Error())
			return
		}
		clientHost = net.JoinHostPort("127.0.0.1", port)

		cmd := exec.Command(kernel, "-host", clientHost)
		log.Println(cmd.String())
		err = cmd.Start()
		if err != nil {
			gui.MessageBox(err.Error())
			return
		}
		defer cmd.Process.Kill()
		go func() {
			err = cmd.Wait()
			if err != nil {
				log.Println(err)
			}
			os.Exit(1)
		}()
	}
	conn, err := grpc.Dial(clientHost, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Println(err)
		gui.MessageBox(err.Error())
		return
	}
	defer conn.Close()
	c := api.NewApiClient(conn)
	_, err = c.ProcessInit(context.Background(), &empty.Empty{})
	if err != nil {
		log.Println(err)
		gui.MessageBox(err.Error())
		return
	}
	defer func() {
		_, err := c.ProcessExit(context.Background(), &empty.Empty{})
		if err != nil {
			log.Println(err)
		}
	}()
	gui.NewGui(c).App.Exec()
}
