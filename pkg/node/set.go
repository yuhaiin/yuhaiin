package node

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/uuid"
)

func init() {
	register.RegisterPoint(NewSet)
}

var GetDialerByID func(ctx context.Context, hash string) (netapi.Proxy, error) = func(ctx context.Context, hash string) (netapi.Proxy, error) {
	return nil, errors.ErrUnsupported
}

// Set
//
// TODO: happyeyeballs?
type Set struct {
	netapi.EmptyDispatch
	Nodes     []string
	randomKey uuid.UUID
	strategy  protocol.SetStrategyType
}

func NewSet(nodes *protocol.Set, _ netapi.Proxy) (netapi.Proxy, error) {
	ns := slices.Compact(nodes.GetNodes())
	if len(ns) == 0 {
		return nil, fmt.Errorf("nodes is empty")
	}

	return &Set{
		Nodes:     ns,
		randomKey: uuid.Random(),
		strategy:  nodes.GetStrategy(),
	}, nil
}

func (s *Set) loop(f func(string) bool) {
	if s.strategy == protocol.Set_round_robin {
		for _, node := range s.Nodes {
			if !f(node) {
				return
			}
		}
	} else {
		for _, i := range rand.Perm(len(s.Nodes)) {
			if !f(s.Nodes[i]) {
				return
			}
		}
	}
}

func (s *Set) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	if ctx.Value(s.randomKey) == true {
		return nil, fmt.Errorf("nested loop is not supported")
	}

	var timeout = configuration.Timeout

	deadline, ok := ctx.Deadline()
	if ok {
		timeout = time.Since(deadline)
	}

	ctx = context.WithoutCancel(ctx)
	ctx = context.WithValue(ctx, s.randomKey, true)

	var err error

	for node := range s.loop {
		dialer, er := GetDialerByID(ctx, node)
		if er != nil {
			err = errors.Join(err, er)
			continue
		}

		ctx, cancel := context.WithTimeout(ctx, timeout)
		conn, er := dialer.Conn(ctx, addr)
		cancel()
		if er != nil {
			err = errors.Join(err, er)
			continue
		}

		return conn, nil
	}

	return nil, err
}

func (s *Set) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	if ctx.Value(s.randomKey) == true {
		return nil, fmt.Errorf("nested loop is not supported")
	}

	ctx = context.WithValue(ctx, s.randomKey, true)

	var err error
	for node := range s.loop {
		dialer, er := GetDialerByID(ctx, node)
		if er != nil {
			err = errors.Join(err, er)
			continue
		}
		conn, er := dialer.PacketConn(ctx, addr)
		if er != nil {
			err = errors.Join(err, er)
			continue
		}

		return conn, nil
	}

	return nil, err
}

func (s *Set) Close() error { return nil }
