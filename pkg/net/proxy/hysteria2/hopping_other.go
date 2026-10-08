//go:build !linux

package hysteria2

import (
	"errors"
	"io"
	"net"
)

func newHopRedirect(net.Addr, string) (io.Closer, error) {
	return nil, errors.New("hysteria2 automatic server port hopping requires Linux; leave hopPorts empty and configure external port forwarding on other platforms")
}
