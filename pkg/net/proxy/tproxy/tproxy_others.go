//go:build !linux
// +build !linux

package tproxy

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func NewServer(string, netapi.Proxy) (netapi.Server, error) {
	return nil, fmt.Errorf("tproxy only support linux")
}
