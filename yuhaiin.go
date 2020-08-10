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
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/therecipe/qt/widgets"

	"github.com/Asutorufa/yuhaiin/gui/sysproxy"

	//_ "net/http/pprof"
	"github.com/Asutorufa/yuhaiin/api"
	"github.com/Asutorufa/yuhaiin/gui"
	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"
)

var (
	extKernel      bool
	clientHost     string
	kernel         string
	cmd            *exec.Cmd
	signChannel    chan os.Signal
	exitFuncCalled bool
	qtApp          *widgets.QApplication
	normalExit     bool
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
			fmt.Printf("kernel -> %s", line)
		}
	}()
	go func() {
		err = cmd.Wait()
		if err != nil {
			log.Println("kernel -> ", err)
		}
		log.Println("kernel stop running")
		exitFunc()
	}()
}

func sigh() {
	signChannel = make(chan os.Signal)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGILL, syscall.SIGFPE, syscall.SIGKILL)
	go func() {
		for s := range signChannel {
			switch s {
			case syscall.SIGHUP:
				log.Println("SIGHUP")
				exitFunc()
			case syscall.SIGINT:
				log.Println("SIGHINT")
				exitFunc()
			case syscall.SIGTERM:
				log.Println("SIGHTERM")
				exitFunc()
			case syscall.SIGILL:
				log.Println("SIGILL")
				exitFunc()
			case syscall.SIGFPE:
				log.Println("SIGFPE")
				exitFunc()
			case syscall.SIGKILL:
				log.Println("SIGKILL")
				exitFunc()
			default:
				fmt.Println("OTHERS SIGN:", s)
			}
		}
	}()
}

func exitFunc() {
	if exitFuncCalled {
		return
	}
	fmt.Println("Start Cleaning Process")
	exitFuncCalled = true

	fmt.Println("Stop kernel")
	if cmd != nil && cmd.Process != nil {
		err := cmd.Process.Kill()
		if err != nil {
			log.Println(err)
		}
	}

	fmt.Println("Unset System Proxy")
	sysproxy.UnsetSysProxy()

	if !normalExit {
		fmt.Println("Not Normal Exit, Stop Qt Application")
		qtApp.Quit()
	}

	os.Exit(0)
}

func main() {
	sigh()
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
	flag.StringVar(&kernel, "kernel", filepath.Dir(path)+"/yuhaiin_kernel", "kernel file")
	if runtime.GOOS == "Windows" {
		flag.StringVar(&kernel, "kernel", filepath.Dir(path)+"\\yuhaiin_kernel.exe", "kernel file")
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

	qtApp = gui.NewGui(c).App
	qtApp.Exec()
	normalExit = true
	exitFunc()
}
