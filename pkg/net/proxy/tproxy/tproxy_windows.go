//go:build windows
// +build windows

package tproxy

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
)

func NewServer(h string) (server.Server, error) {
	return nil, fmt.Errorf("tproxy not support for windows")
}
