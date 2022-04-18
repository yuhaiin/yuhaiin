//go:build windows
// +build windows

package server

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

func NewServer(host string, _ proxy.Proxy) (proxy.Server, error) {
	return &proxy.EmptyServer{}, nil
}
