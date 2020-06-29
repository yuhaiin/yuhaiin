// +build !api

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/Asutorufa/yuhaiin/api"
	"github.com/Asutorufa/yuhaiin/process/controller"
	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"

	//_ "net/http/pprof"

	"github.com/Asutorufa/yuhaiin/gui"
)

var (
	extKernel  bool
	clientHost string
	kernel     string
	cmd        *exec.Cmd
)

func startGrpc() {
	fmt.Println("start grpc server")
	port, err := controller.GetFreePort()
	if err != nil {
		gui.MessageBox(err.Error())
		return
	}
	clientHost = net.JoinHostPort("127.0.0.1", port)

	cmd = exec.Command(kernel, "-host", clientHost)
	log.Println(cmd.String())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Println(err)
		gui.MessageBox(err.Error())
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Println(err)
		gui.MessageBox(err.Error())
	}
	err = cmd.Start()
	if err != nil {
		gui.MessageBox(err.Error())
		panic(err)
	}
	stdoutReader := bufio.NewReader(stdout)
	stderrReader := bufio.NewReader(stderr)
	go func() {
		for {
			line, err := stdoutReader.ReadString('\n')
			if err != nil || err == io.EOF {
				break
			}
			fmt.Printf("kernel -> %s", line)
		}
	}()
	go func() {
		for {
			line, err := stderrReader.ReadString('\n')
			if err != nil || err == io.EOF {
				break
			}
			log.Printf("kernel -> %s", line)
		}
	}()
	go func() {
		err = cmd.Wait()
		if err != nil {
			log.Println(err)
		}
		panic("kernel stop running")
	}()
}

func main() {
	//go func() {
	//	// 开启pprof，监听请求
	//	ip := "0.0.0.0:6060"
	//	if err := http.ListenAndServe(ip, nil); err != nil {
	//		fmt.Printf("start pprof failed on %s\n", ip)
	//	}
	//}()

	log.SetFlags(log.Llongfile)

	flag.BoolVar(&extKernel, "nokernel", false, "not run kernel")
	flag.StringVar(&clientHost, "host", "127.0.0.1:50051", "kernel rpc host")

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
	flag.StringVar(&kernel, "kernel", filepath.Dir(path)+"/kernel", "kernel file")
	if runtime.GOOS == "Windows" {
		flag.StringVar(&kernel, "kernel", filepath.Dir(path)+"\\kernel.exe", "kernel file")
	}
	flag.Parse()

	if !extKernel {
		startGrpc()
		defer cmd.Process.Kill()
	}

	fmt.Printf("grpc dial: %s\n", clientHost)
	conn, err := grpc.Dial(clientHost, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Println(err)
		gui.MessageBox(err.Error())
		return
	}
	defer conn.Close()
	fmt.Println("new api client")
	c := api.NewApiClient(conn)
	fmt.Println("process init")
	s, err := c.ProcessInit(context.Background(), &empty.Empty{})
	if s == nil || err != nil {
		log.Println(s)
		gui.MessageBox(err.Error())
		panic(err)
	}
	if s.Value != "" {
		err = conn.Close()
		if err != nil {
			panic(err)
		}
		conn, err = grpc.Dial(s.Value, grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			panic(err)
		}
		defer conn.Close()
		c = api.NewApiClient(conn)
		_, err = c.ClientOn(context.Background(), &empty.Empty{})
		if err != nil {
			panic(err)
		}
		return
	}
	defer func() {
		_, err := c.ProcessExit(context.Background(), &empty.Empty{})
		if err != nil {
			log.Println(err)
		}
	}()
	fmt.Println("open ui")
	gui.NewGui(c).App.Exec()
}
