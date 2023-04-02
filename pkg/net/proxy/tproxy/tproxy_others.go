//go:build !linux
// +build !linux

package tproxy

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	is "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
)

func NewServer(h string, dialer proxy.Proxy) (is.Server, error) {
	return nil, fmt.Errorf("tproxy only support linux")
}
