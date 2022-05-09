//go:build windows
// +build windows

package server

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/server"
)

func NewServer(host string, _ proxy.Proxy) (iserver.Server, error) {
	return &server.EmptyServer{}, nil
}
