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
	"strconv"
	"time"

	//_ "net/http/pprof"
	"github.com/Asutorufa/yuhaiin/api"
	"github.com/Asutorufa/yuhaiin/gui"
	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"
)

var (
	extKernel  bool
	clientHost string
	kernel     string
	cmd        *exec.Cmd
)

func getFreePort() (string, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return "", err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := l.Close(); err != nil {
			log.Println(err)
		}
	}()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port), nil
}

func startGrpc() {
	fmt.Println("Try start kernel.")
	port, err := getFreePort()
	if err != nil {
		gui.MessageBox(err.Error())
		return
	}
	clientHost = net.JoinHostPort("127.0.0.1", port)
	fmt.Println("gRPC Host:", clientHost)
	cmd = exec.Command(kernel, "-host", clientHost)
	fmt.Println("Start kernel command:", cmd.String())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Println("Get standard output failed:", err)
		gui.MessageBox(err.Error())
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Println("Get standard error failed:", err)
		gui.MessageBox(err.Error())
	}
	fmt.Println("Try to running kernel command.")
	err = cmd.Start()
	if err != nil {
		log.Println("Running kernel command failed:", err)
		gui.MessageBox(err.Error())
		panic(err)
	}
	fmt.Println("Running kernel command successful.")
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

	fmt.Println("Use external:", extKernel)
	fmt.Println("Kernel Path:", kernel)
	if !extKernel {
		startGrpc()
		defer cmd.Process.Kill()
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	fmt.Println("Try to Create gRPC Dial.")
	conn, err := grpc.DialContext(ctx, clientHost, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Println("Create gRPC Dial failed:", err)
		gui.MessageBox(err.Error())
		return
	}
	fmt.Println("Create gRPC Dial successful.")
	defer conn.Close()
	fmt.Println("Create API Client.")
	c := api.NewApiClient(conn)
	fmt.Println("Try to Get lock file state.")
	_, err = c.CreateLockFile(context.Background(), &empty.Empty{})
	if err != nil {
		log.Println(err)
		fmt.Println("Try to Get Already Running kernel gRPC Host.")
		s, err := c.GetRunningHost(context.Background(), &empty.Empty{})
		if err != nil {
			fmt.Println("Get Already Running kernel gRPC Host failed.")
			panic(err)
		}
		err = conn.Close()
		if err != nil {
			panic(err)
		}
		fmt.Println("Get Running Host Successful, Host:", s.Value)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
		defer cancel()
		fmt.Println("Try to Create gRPC Dial.")
		conn, err = grpc.DialContext(ctx, s.Value, grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			fmt.Println("Create gRPC Dial failed:", err)
			panic(err)
		}
		fmt.Println("Create gRPC Dial successful.")
		defer conn.Close()
		c = api.NewApiClient(conn)
		fmt.Println("Try to Open GUI.")
		_, err = c.ClientOn(context.Background(), &empty.Empty{})
		if err != nil {
			fmt.Println("Open GUI failed:", err)
			panic(err)
		}
		fmt.Println("Open GUI Successful.")
		return
	}
	//fmt.Println("Try process init")
	//_, err = c.ProcessInit(context.Background(), &empty.Empty{})
	//if err != nil {
	//	panic(err)
	//}
	defer func() {
		_, err := c.ProcessExit(context.Background(), &empty.Empty{})
		if err != nil {
			log.Println(err)
		}
	}()
	fmt.Println("Open GUI.")
	gui.NewGui(c).App.Exec()
}
