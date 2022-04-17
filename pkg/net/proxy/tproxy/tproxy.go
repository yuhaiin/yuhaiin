//go:build !windows
// +build !windows

package tproxy

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

// modified from https://github.com/LiamHaworth/go-tproxy

func NewServer(h string, dialer proxy.Proxy) (proxy.Server, error) {
	t, err := newTCPServer(h, dialer)
	if err != nil {
		return nil, fmt.Errorf("create tcp server failed: %w", err)
	}
	u, err := newUDPServer(h, dialer)
	if err != nil {
		return nil, fmt.Errorf("create udp server failed: %w", err)
	}
	return &server{tcp: t, udp: u}, nil
}

type server struct {
	tcp proxy.Server
	udp proxy.Server
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
