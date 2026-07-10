//go:build linux

package tproxy

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type Tproxy struct {
	netapi.EmptyInterface
	lis netapi.Listener

	lisAddr *net.TCPAddr
	handler netapi.Handler
	ctx     context.Context
	cancel  context.CancelFunc
}

type ServerConfig struct {
}

func NewTproxy(_ ServerConfig, ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	ctx, cancel := context.WithCancel(context.Background())

	t := &Tproxy{
		lis:     ii,
		handler: handler,
		ctx:     ctx,
		cancel:  cancel,
	}

	if err := t.newTCP(); err != nil {
		return nil, err
	}

	if err := t.newUDP(); err != nil {
		t.Close()
		return nil, err
	}

	return t, nil
}

func (t *Tproxy) Close() error {
	t.cancel()
	return t.lis.Close()
}
