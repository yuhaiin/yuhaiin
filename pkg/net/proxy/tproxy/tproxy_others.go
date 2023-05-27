//go:build !linux
// +build !linux

package tproxy

import (
	"fmt"

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
)

func NewServer(string, proxy.Proxy) (proxy.Server, error) {
	return nil, fmt.Errorf("tproxy only support linux")
}
