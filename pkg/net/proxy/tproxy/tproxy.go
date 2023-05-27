//go:build linux
// +build linux

package tproxy

import (
	"fmt"

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
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
	return &tproxy{tcp: t, udp: u}, nil
}

type tproxy struct {
	tcp proxy.Server
	udp proxy.Server
}

func (s *tproxy) Close() error {
	err := s.tcp.Close()
	if err != nil {
		return fmt.Errorf("socks5 tcp close server failed: %w", err)
	}
	err = s.udp.Close()
	if err != nil {
		return fmt.Errorf("socks5 udp close server failed: %w", err)
	}
	return nil
}
