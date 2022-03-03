//go:build windows
// +build windows

package server

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

func RedirHandle() func(net.Conn, proxy.Proxy) {
	return nil
}

func NewServer(host string) (proxy.Server, error) {
	return &proxy.EmptyServer{}, nil
}
