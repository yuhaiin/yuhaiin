package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
)

// Set
//
// TODO: happyeyeballs?
type Set struct {
	netapi.EmptyDispatch
	manager   *Manager
	outbound  *outbound
	Nodes     []string
	randomKey id.UUID
	strategy  protocol.SetStrategyType

	lastID atomic.Int32
}

func NewSet(nodes *protocol.Set, m *Manager) (netapi.Proxy, error) {
	ns := slices.Compact(nodes.GetNodes())
	if len(ns) == 0 {
		return nil, fmt.Errorf("nodes is empty")
	}

	s := &Set{
		manager:   m,
		outbound:  m.Outbound(),
		Nodes:     ns,
		randomKey: id.GenerateUUID(),
		strategy:  nodes.GetStrategy(),
	}

	s.lastID.Store(-1)

	return s, nil
}

func (s *Set) loop(f func(int, string) bool) {
	cacheIndex := s.lastID.Load()
	if cacheIndex >= 0 {
		if !f(int(cacheIndex), s.Nodes[cacheIndex]) {
			return
		}
	}

	if s.strategy == protocol.Set_round_robin {
		for i, node := range s.Nodes {
			if i == int(cacheIndex) {
				continue
			}

			if !f(i, node) {
				return
			}
		}
	} else {
		for _, i := range rand.Perm(len(s.Nodes)) {
			if i == int(cacheIndex) {
				continue
			}

			if !f(i, s.Nodes[i]) {
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
	return setDo(s, ctx, true, func(ctx context.Context, dialer netapi.Proxy) (net.Conn, error) {
		return dialer.Conn(ctx, addr)
	})
}

func (s *Set) storeIndex(i int) {
	if s.lastID.Load() == int32(i) {
		return
	}

	s.lastID.Store(int32(i))
}

func setDo[T io.Closer](s *Set, ctx context.Context, storeIndex bool, f func(context.Context, netapi.Proxy) (T, error)) (T, error) {
	ctx, err := s.nestedLoopCounter(ctx)
	if err != nil {
		return *new(T), err
	}

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)

	ch := make(chan T)

	go func() {
		var (
			wg        sync.WaitGroup
			emu       sync.Mutex
			failBoost = make(chan struct{}) // best effort send on dial failure
		)

		appendError := func(er error) {
			emu.Lock()
			err = errors.Join(err, er)
			emu.Unlock()
		}

		for i, node := range s.loop {
			dialer, er := s.outbound.GetDialerByID(ctx, node)
			if er != nil {
				appendError(er)
				continue
			}

			wg.Go(func() {
				conn, er := f(ctx, dialer)
				if er != nil {
					appendError(er)
					select {
					case failBoost <- struct{}{}:
					default:
					}
					return
				}

				select {
				case ch <- conn:
					if storeIndex {
						s.storeIndex(i)
					}
				case <-ctx.Done():
					_ = conn.Close()
				}
			})

			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-failBoost:
				timer.Stop()
			case <-timer.C:
			}
		}

		wg.Wait()
		cancel(err)
	}()

	select {
	case <-ctx.Done():
		return *new(T), context.Cause(ctx)
	case conn := <-ch:
		return conn, nil
	}
}

func (s *Set) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return setDo(s, ctx, false, func(ctx context.Context, dialer netapi.Proxy) (net.PacketConn, error) {
		return dialer.PacketConn(ctx, addr)
	})
}

func (s *Set) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	ctx, err := s.nestedLoopCounter(ctx)
	if err != nil {
		return 0, err
	}

	for _, node := range s.loop {
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
		ps := s.manager.GetUsingPoints()
		for _, v := range s.Nodes {
			// TODO skip myself
			if !ps.Has(v) {
				s.manager.Store().Delete(v)
			}
		}
	}()

	return nil
}
