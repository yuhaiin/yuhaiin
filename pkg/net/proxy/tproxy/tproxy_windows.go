//+build windows

package tproxy

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

func NewServer(h string) (proxy.Server, error) {
	return nil, fmt.Errorf("tproxy not support for windows")
}
