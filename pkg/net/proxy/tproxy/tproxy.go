//+build !windows
package tproxy

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

// modified from https://github.com/LiamHaworth/go-tproxy

func NewServer(h string) (proxy.Server, error) {
	t, err := newTCPServer(h)
	if err != nil {
		return nil, fmt.Errorf("create tcp server failed: %w", err)
	}
	u, err := newUDPServer(h)
	if err != nil {
		return nil, fmt.Errorf("create udp server failed: %w", err)
	}
	return &server{tcp: t, udp: u}, nil
}

type server struct {
	tcp proxy.Server
	udp proxy.Server
}

func (s *server) SetProxy(p proxy.Proxy) {
	s.tcp.SetProxy(p)
	s.udp.SetProxy(p)
}

func (s *server) SetServer(host string) error {
	err := s.tcp.SetServer(host)
	if err != nil {
		return fmt.Errorf("socks5 tcp server set host failed: %v", err)
	}
	err = s.udp.SetServer(host)
	if err != nil {
		return fmt.Errorf("socks5 udp server set host failed: %v", err)
	}
	return nil
}

func (s *server) Close() error {
	err := s.tcp.Close()
	if err != nil {
		return fmt.Errorf("socks5 tcp close server failed: %v", err)
	}
	err = s.udp.Close()
	if err != nil {
		return fmt.Errorf("socks5 udp close server failed: %v", err)
	}
	return nil
}
