package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
)

// tcpserver tcp server common
type tcpserver struct {
	listener net.Listener
}

type tcpOpt struct {
	config net.ListenConfig
}

func TCPWithListenConfig(n net.ListenConfig) func(u *tcpOpt) {
	return func(u *tcpOpt) {
		u.config = n
	}
}

// NewTCPServer create new TCP listener
func NewTCPServer(host string, handle func(net.Conn), opt ...func(*tcpOpt)) (server.Server, error) {
	if host == "" {
		return nil, fmt.Errorf("host is empty")
	}

	if handle == nil {
		return nil, fmt.Errorf("handle is empty")
	}

	s := &tcpOpt{config: net.ListenConfig{}}

	for i := range opt {
		opt[i](s)
	}

	tcp := &tcpserver{}
	err := tcp.run(host, s.config, handle)
	if err != nil {
		return nil, fmt.Errorf("tcp server run failed: %v", err)
	}
	return tcp, nil
}

func (t *tcpserver) run(host string, config net.ListenConfig, handle func(net.Conn)) (err error) {
	t.listener, err = config.Listen(context.TODO(), "tcp", host)
	if err != nil {
		return fmt.Errorf("tcp server listen failed: %v", err)
	}

	log.Println("new tcp server listen at:", host)

	go func() {
		err := t.process(handle)
		if err != nil {
			log.Println(err)
		}
	}()
	return
}

func (t *tcpserver) process(handle func(net.Conn)) error {
	var tempDelay time.Duration
	for {
		c, err := t.listener.Accept()
		if err != nil {
			// from https://golang.org/src/net/http/server.go?s=93655:93701#L2977
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}

				if max := 5 * time.Second; tempDelay > max {
					tempDelay = max
				}

				log.Printf("tcp sever: Accept error: %v; retrying in %v\n", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}

			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("checked tcp server closed: %w", err)
			} else {
				return fmt.Errorf("tcp server accept failed: %w", err)
			}
		}

		tempDelay = 0

		go func() {
			if runtime.GOOS != "windows" {
// 				if c, ok := c.(*net.TCPConn); ok {
// 					raw, err := c.SyscallConn()
// 					if err != nil {
// 						log.Println(err)
// 					} else {
// 						raw.Control(func(fd uintptr) {
// 							// which is the system socket (type is plateform specific - Int for linux)
// 							ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
// 							if err != nil {
// 								log.Printf("tcp server: GetsockoptUcred failed: %v\n", err)
// 							} else {
// 								fmt.Printf("peer_pid: %d\n", ucred.Pid)
// 								fmt.Printf("peer_uid: %d\n", ucred.Uid)
// 								fmt.Printf("peer_gid: %d\n", ucred.Gid)
// 								fmt.Println(user.LookupId(strconv.Itoa(int(ucred.Uid))))
// 							}
// 						})
// 					}
// 				}
				// fdVal := reflect.Indirect(reflect.ValueOf(c)).FieldByName("fd")
				// pfdVal := reflect.Indirect(fdVal).FieldByName("pfd")
				// cfd := int(pfdVal.FieldByName("Sysfd").Int())

				// // which is the system socket (type is plateform specific - Int for linux)
				// ucred, err := syscall.GetsockoptUcred(cfd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
				// if err != nil {
				// 	log.Printf("tcp server: GetsockoptUcred failed: %v\n", err)
				// } else {
				// 	// fmt.Printf("peer_pid: %d\n", ucred.Pid)
				// 	fmt.Printf("peer_uid: %d\n", ucred.Uid)
				// 	// fmt.Printf("peer_gid: %d\n", ucred.Gid)
				// 	fmt.Println(user.LookupId(strconv.Itoa(int(ucred.Uid))))
				// }
			}
			defer c.Close()
			handle(c)
		}()
	}
}

func (t *tcpserver) Close() error {
	if t.listener == nil {
		return nil
	}
	return t.listener.Close()
}

func (t *tcpserver) Addr() net.Addr {
	if t.listener == nil {
		return &net.TCPAddr{}
	}

	return t.listener.Addr()
}
