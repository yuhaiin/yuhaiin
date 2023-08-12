package tproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type udpserver struct {
	listener net.PacketConn
}

type udpOpt struct {
	config     net.ListenConfig
	handle     func(io.Reader) (io.ReadCloser, error)
	listenFunc func(net.PacketConn) error
}

func UDPWithListenConfig(n net.ListenConfig) func(u *udpOpt) {
	return func(u *udpOpt) {
		u.config = n
	}
}

func UDPWithListenFunc(f func(net.PacketConn) error) func(u *udpOpt) {
	return func(u *udpOpt) {
		u.listenFunc = f
	}
}

func UDPWithHandle(f func(req io.Reader) (resp io.ReadCloser, err error)) func(u *udpOpt) {
	return func(u *udpOpt) {
		u.handle = f
	}
}

func NewUDPServer(host string, opt ...func(u *udpOpt)) (netapi.Server, error) {
	if host == "" {
		return nil, fmt.Errorf("host not defined")
	}

	udp := &udpserver{}
	u := &udpOpt{config: net.ListenConfig{}}
	for i := range opt {
		opt[i](u)
	}

	if u.listenFunc == nil && u.handle == nil {
		return nil, fmt.Errorf("udp server must define listen func or handle func")
	}

	if u.listenFunc == nil && u.handle != nil {
		u.listenFunc = func(pc net.PacketConn) error { return udp.defaultListenFunc(pc, u.handle) }
	}

	err := udp.run(host, u.config, u.listenFunc)
	if err != nil {
		return nil, fmt.Errorf("udp server run failed: %w", err)
	}
	return udp, nil
}

func (u *udpserver) Close() error {
	if u.listener == nil {
		return nil
	}
	return u.listener.Close()
}

func (u *udpserver) Addr() net.Addr {
	if u.listener == nil {
		return &net.UDPAddr{}
	}
	return u.listener.LocalAddr()
}

func (u *udpserver) run(host string, config net.ListenConfig, listenFunc func(net.PacketConn) error) (err error) {
	u.listener, err = config.ListenPacket(context.TODO(), "udp", host)
	if err != nil {
		return fmt.Errorf("udp server listen failed: %w", err)
	}

	log.Debug("new udp server", "host", host)
	go func() {
		err := listenFunc(u.listener)
		if err != nil {
			log.Error("listen failed", "err", err)
		}
	}()
	return nil
}

func (u *udpserver) defaultListenFunc(l net.PacketConn, handle func(io.Reader) (io.ReadCloser, error)) error {
	var tempDelay time.Duration
	for {
		b := make([]byte, 1024)
		n, remoteAddr, err := l.ReadFrom(b)
		if err != nil {
			// from https://golang.org/src/net/http/server.go?s=93655:93701#L2977
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}

				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}

				log.Warn(fmt.Sprintf("tcp sever: Accept failed retrying in %v", tempDelay), "err", err)
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

		go func(b []byte, remoteAddr net.Addr) {
			data, err := handle(bytes.NewReader(b))
			if err != nil {
				log.Error("udp handle failed", "err", err)
				return
			}
			defer data.Close()

			for {
				n, err := data.Read(b)
				if err != nil {
					if !errors.Is(err, io.EOF) {
						log.Error("udp handle read failed", "err", err)
					}
					break
				}

				_, err = l.WriteTo(b[:n], remoteAddr)
				if err != nil {
					log.Error("udp listener write to client failed", "err", err)
					break
				}
			}
		}(b[:n], remoteAddr)
	}
}
