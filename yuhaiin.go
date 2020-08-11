// +build !api

package main

import (
	"bufio"
	"context"
	"errors"
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

	apiClient  api.ApiClient
	clientConn *grpc.ClientConn
	exitCall   []func()

	conn2c  bool
	conn2S  = errors.New("connect Exists Client Successful")
	conn2Re = errors.New("retry Connect Kernel")
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
	if extKernel {
		return
	}
	fmt.Println("Try start kernel.")
	port, err := getFreePort()
	if err != nil {
		gui.MessageBox(err.Error())
		return
	}
	clientHost = net.JoinHostPort("127.0.0.1", port)
	fmt.Println("gRPC Host:", clientHost)
	cmd = exec.Command(kernel, "-host", clientHost, "-kwdc")
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
	exitCall = append(exitCall, func() {
		fmt.Println("Stop kernel")
		if cmd != nil && cmd.Process != nil {
			err := cmd.Process.Kill()
			if err != nil {
				log.Println(err)
			}
		}
	})
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
		err := cmd.Wait()
		if err != nil {
			log.Println("kernel -> ", err)
		}
		if conn2c {
			conn2c = false
			return
		}
		log.Println("kernel stop running")
		exitFunc()
	}()
}

func sigh() {
	//https://colobu.com/2015/10/09/Linux-Signals/
	signChannel = make(chan os.Signal)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		for s := range signChannel {
			switch s {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
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

	for index := range exitCall {
		exitCall[index]()
	}
	fmt.Println("Unset System Proxy")
	sysproxy.UnsetSysProxy()

	os.Exit(0)
}

func execPath() string {
	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		panic(err)
	}
	path, err := filepath.Abs(file)
	if err != nil {
		panic(err)
	}
	return filepath.Dir(path)
}

func main() {
	sigh()

	log.SetFlags(log.Llongfile)
	flag.BoolVar(&extKernel, "nokernel", false, "not run kernel")
	flag.StringVar(&clientHost, "host", "127.0.0.1:50051", "kernel rpc host")
	if runtime.GOOS == "windows" {
		flag.StringVar(&kernel, "kernel", execPath()+"\\yuhaiin_kernel.exe", "kernel file")
	} else {
		flag.StringVar(&kernel, "kernel", execPath()+"/yuhaiin_kernel", "kernel file")
	}
	flag.Parse()

_reConnectGrpc:
	fmt.Println("Use external:", extKernel)
	fmt.Println("Kernel Path:", kernel)
	startGrpc()
	var err error
	ctx, _ := context.WithTimeout(context.Background(), time.Second*3)
	fmt.Println("Try to Create gRPC Dial.")
	clientConn, err = grpc.DialContext(ctx, clientHost, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Println("Create gRPC Dial failed:", err)
		gui.MessageBox(err.Error())
		return
	}
	fmt.Println("Create gRPC Dial successful.")
	defer func() {
		_ = clientConn.Close()
	}()
	fmt.Println("Create API Client.")
	apiClient = api.NewApiClient(clientConn)
	err = checkLockFile()
	if err == conn2Re {
		goto _reConnectGrpc
	}
	if err == conn2S {
		return
	}
	if err != nil {
		panic(err)
	}

	fmt.Println("Open GUI.")

	qtApp = gui.NewGui(apiClient).App
	qtApp.Exec()
	defer exitFunc()
}

func checkLockFile() (err error) {
	fmt.Println("Try to Get lock file state.")
	_, err = apiClient.CreateLockFile(context.Background(), &empty.Empty{})
	if err != nil {
		log.Println(err)
		fmt.Println("Try to Get Already Running kernel gRPC Host.")
		s, err := apiClient.GetRunningHost(context.Background(), &empty.Empty{})
		if err != nil {
			fmt.Println("Get Already Running kernel gRPC Host failed.")
			return err
		}
		err = clientConn.Close()
		if err != nil {
			return err
		}
		fmt.Println("Get Running Host Successful, Host:", s.Value)
		ctx, _ := context.WithTimeout(context.Background(), time.Second*3)
		fmt.Println("Try to Create gRPC Dial.")
		clientConn, err = grpc.DialContext(ctx, s.Value, grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			fmt.Println("Create gRPC Dial failed:", err)
			return err
		}
		fmt.Println("Create gRPC Dial successful.")
		apiClient = api.NewApiClient(clientConn)
		fmt.Println("Try to Open GUI.")
		_, err = apiClient.ClientOn(context.Background(), &empty.Empty{})
		if err != nil {
			fmt.Println("Call exists GUI failed:", err)
			fmt.Println("Try to Stop exists kernel")
			kernelPid, err := apiClient.GetKernelPid(context.Background(), &empty.Empty{})
			if err != nil {
				return err
			}
			fmt.Println("Get Kernel Pid ", kernelPid.Value)
			process, err := os.FindProcess(int(kernelPid.Value))
			if err != nil {
				return err
			}
			fmt.Println("Kill exists Kernel ", kernelPid.Value)
			err = process.Kill()
			if err != nil {
				return err
			}
			err = clientConn.Close()
			if err != nil {
				return err
			}
			conn2c = true
			fmt.Println("Kill cmd and ReStart Kernel")
			if cmd != nil && cmd.Process != nil {
				err = cmd.Process.Kill()
				if err != nil {
					log.Println(err)
				}
			}
			fmt.Println("Try to ReConnect")
			return conn2Re
		}
		fmt.Println("Open GUI Successful.")
		return conn2S
	}
	return
}
