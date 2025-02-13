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
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/uuid"
)

// Set
//
// TODO: happyeyeballs?
type Set struct {
	netapi.EmptyDispatch
	manager   *Manager
	outbound  *outbound
	Nodes     []string
	randomKey uuid.UUID
	strategy  protocol.SetStrategyType
}

func NewSet(nodes *protocol.Set, m *Manager) (netapi.Proxy, error) {
	ns := slices.Compact(nodes.GetNodes())
	if len(ns) == 0 {
		return nil, fmt.Errorf("nodes is empty")
	}

	return &Set{
		manager:   m,
		outbound:  m.Outbound(),
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
		timeout = time.Until(deadline)
	}

	ctx = context.WithoutCancel(ctx)
	ctx = context.WithValue(ctx, s.randomKey, true)

	var err error

	for node := range s.loop {
		dialer, er := s.outbound.GetDialerByID(ctx, node)
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
		dialer, er := s.outbound.GetDialerByID(ctx, node)
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

func (s *Set) Close() error {
	// TODO
	// because here is called from manager
	// so the mu is already locked, we can't get locker here
	// so we need to do it in goroutine
	go func() {
		err := s.manager.db.View(func(n *Node) error {
			ps := n.GetUsingPoints()
			for _, v := range s.Nodes {
				// TODO skip myself
				if !ps.Has(v) {
					s.manager.store.Delete(v)
				}
			}
			return nil
		})
		if err != nil {
			log.Warn("close set failed", "err", err)
		}
	}()

	return nil
}
