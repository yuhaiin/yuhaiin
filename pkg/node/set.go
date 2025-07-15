package node

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/google/uuid"
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
		randomKey: uuid.New(),
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

func (s *Set) nestedLoopCounter(ctx context.Context) (context.Context, error) {
	c, ok := ctx.Value(s.randomKey).(*atomic.Uint64)
	if !ok {
		c = new(atomic.Uint64)
		c.Add(1)
		ctx = context.WithValue(ctx, s.randomKey, c)
		return ctx, nil
	}

	if c.Add(1) > 10 {
		return ctx, fmt.Errorf("nested looped more than 10 times, for skip infinite loop, abort")
	}

	return ctx, nil
}

func (s *Set) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	ctx, err := s.nestedLoopCounter(ctx)
	if err != nil {
		return nil, err
	}

	var timeout = configuration.Timeout

	deadline, ok := ctx.Deadline()
	if ok {
		timeout = time.Until(deadline)
	}

	ctx = context.WithoutCancel(ctx)

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
	ctx, err := s.nestedLoopCounter(ctx)
	if err != nil {
		return nil, err
	}

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

func (s *Set) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	ctx, err := s.nestedLoopCounter(ctx)
	if err != nil {
		return 0, err
	}

	for node := range s.loop {
		dialer, er := s.outbound.GetDialerByID(ctx, node)
		if er != nil {
			err = errors.Join(err, er)
			continue
		}
		resp, er := dialer.Ping(ctx, addr)
		if er != nil {
			err = errors.Join(err, er)
			continue
		}

		return resp, nil
	}

	return 0, err
}

func (s *Set) Close() error {
	// Close
	//
	// Close the set. This will remove all unused nodes in the set.

	// TODO
	// because here is called from manager, the mu is already locked, we can't get locker here
	// so we need to do it in goroutine
	go func() {
		err := s.manager.db.View(func(n *Node) error {
			ps := n.GetUsingPoints()
			for _, v := range s.Nodes {
				// TODO skip myself
				if !ps.Has(v) {
					s.manager.GetStore().Delete(v)
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
