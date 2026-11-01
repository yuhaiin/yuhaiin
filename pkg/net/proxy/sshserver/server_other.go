//go:build !linux || android

package sshserver

import (
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// Server is unavailable outside Linux hosts (Android is not supported).
type Server struct{ netapi.EmptyInterface }

func NewServer(Config, netapi.Handler) (*Server, error) {
	return nil, errors.New("ssh inbound requires Linux with network namespace privileges")
}

func (*Server) Close() error { return nil }
