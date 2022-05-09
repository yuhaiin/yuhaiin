//go:build windows
// +build windows

package tproxy

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/interfaces"
)

func NewServer(h string) (interfaces.Server, error) {
	return nil, fmt.Errorf("tproxy not support for windows")
}
