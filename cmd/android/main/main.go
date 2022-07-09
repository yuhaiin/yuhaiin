package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	yuhaiin "github.com/Asutorufa/yuhaiin/cmd/android"
)

var app = &yuhaiin.App{}

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	log.SetOutput(os.Stdout)

	signChannel := make(chan os.Signal, 1)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	exit := make(chan bool)
	// listen system signal
	go func() {
		z := <-signChannel
		log.Println("receive signal:", z.String())
		if err := app.Stop(); err != nil {
			log.Println("stop failed:", err)
		}
		log.Println("exit process")
		exit <- true
	}()

	log.Println(os.Args[1])

	// optD, err := base64.StdEncoding.DecodeString(os.Args[1])
	// if err != nil {
	// log.Fatal("decode config failed: ", err)
	// }

	var err error
	optD := os.Args[1]

	// log.Println("config:", string(optD))

	opt := &yuhaiin.Opts{}
	if err := json.Unmarshal([]byte(optD), opt); err != nil {
		log.Fatal(err)
	}

	opt.TUN.FD, err = getTunFD(os.Args[2])
	if err != nil {
		log.Fatal("get tun fd failed:", err)
	}
	defer syscall.Close(int(opt.TUN.FD))

	if err := app.Start(opt); err != nil {
		log.Fatal(err)
	}

	<-exit
}

func getTunFD(file string) (int32, error) {
	os.RemoveAll(file)
	defer os.RemoveAll(file)
	log.Println("getTunFD listen at:", file)
	n, err := net.Listen("unix", file)
	if err != nil {
		return 0, fmt.Errorf("listen unix file failed: %v", err)
	}
	defer n.Close()

	for {
		conn, err := n.Accept()
		if err != nil {
			return 0, fmt.Errorf("accept failed: %v", err)
		}

		fd, err := getFDFromConn(conn)
		if err != nil {
			log.Println("get fd failed:", err)
			continue
		}

		return int32(fd), nil
	}
}

func getFDFromConn(conn net.Conn) (fd int, err error) {
	defer conn.Close()
	sysConn, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("get syscallConn failed: %v", err)
	}
	var connFd uintptr
	sysConn.Control(func(fd uintptr) {
		connFd = fd
	})

	buf := make([]byte, syscall.CmsgSpace(1*4))

	tries := 0
	for {
		_, _, _, _, err = syscall.Recvmsg(int(connFd), nil, buf, 0)
		if err == nil {
			break
		}

		log.Println("tries(", tries, ") recvmsg failed:", err)

		if tries > 5 {
			panic(fmt.Sprintf("recvmsg failed: %v", err))
		}

		time.Sleep((50 << tries) * time.Millisecond)
		tries++
		continue
	}

	ccs, err := syscall.ParseSocketControlMessage(buf)
	if err != nil {
		return 0, fmt.Errorf("parse socket control message failed: %v", err)
	}

	fds, err := syscall.ParseUnixRights(&ccs[0])
	if err != nil {
		return 0, fmt.Errorf("parseUnixRights failed: %v", err)
	}

	log.Println("get fd:", fds[0])

	return fds[0], nil
}

func getConfig(conn net.Conn) ([]byte, error) {
	length := make([]byte, 2)
	_, err := io.ReadFull(conn, length)
	if err != nil {
		return nil, fmt.Errorf("read length failed: %v", err)
	}

	l := int(length[0])<<8 + int(length[1])

	data := make([]byte, l)
	_, err = io.ReadFull(conn, data)
	if err != nil {
		return nil, fmt.Errorf("read data(%d) failed: %v", l, err)
	}

	log.Println("get config:", string(data))
	return data, nil
}
