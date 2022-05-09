package server

import (
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
)

var _ server.Server = (*EmptyServer)(nil)

type EmptyServer struct{}

func (e *EmptyServer) Close() error { return nil }

func (e *EmptyServer) Addr() net.Addr { return &net.TCPAddr{} }
