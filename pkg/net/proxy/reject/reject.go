package reject

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

var _ netapi.Proxy = (*reject)(nil)

type rejectImmediately struct{ netapi.EmptyDispatch }

func (rejectImmediately) Conn(_ context.Context, addr netapi.Address) (net.Conn, error) {
	return nil, &net.OpError{
		Op:   "block",
		Net:  addr.Network(),
		Addr: addr,
		Err:  errors.New("blocked"),
	}
}

func (r rejectImmediately) PacketConn(_ context.Context, addr netapi.Address) (net.PacketConn, error) {
	_, err := r.Conn(context.Background(), addr)
	return nil, err
}

func (r rejectImmediately) Ping(_ context.Context, addr netapi.Address) (uint64, error) {
	_, err := r.Conn(context.Background(), addr)
	return 0, err
}

func (rejectImmediately) Close() error { return nil }

type reject struct {
	netapi.EmptyDispatch
	cache         *lru.SyncLru[string, object]
	max, internal int
}

type object struct {
	time  time.Time
	delay time.Duration
	times int8
}

func init() {
	register.RegisterPoint(func(*node.Reject, netapi.Proxy) (netapi.Proxy, error) {
		return Default, nil
	})
}

var Default = rejectImmediately{}

func NewReject(maxDelay, interval int) netapi.Proxy {
	return &reject{cache: lru.NewSyncLru(lru.WithCapacity[string, object](100)), max: maxDelay, internal: interval}
}

func (r *reject) delay(addr netapi.Address) time.Duration {
	if r.max == 0 {
		return 0
	}
	z, ok := r.cache.Load(addr.Hostname())
	if !ok || !z.time.Add(time.Duration(r.internal)*time.Second).After(time.Now()) {
		r.cache.Add(addr.Hostname(), object{time: time.Now(), delay: 0, times: 0})
		return 0
	}

	if z.times < 7 {
		z.times++
	}

	if z.times >= 7 && z.delay < time.Second*time.Duration(r.max) {
		z.delay = z.delay + time.Second
	}

	time.Sleep(z.delay)
	r.cache.Add(addr.Hostname(), object{time.Now(), z.delay, z.times})
	return z.delay
}

func (r *reject) Conn(_ context.Context, addr netapi.Address) (net.Conn, error) {
	return nil, fmt.Errorf("blocked address tcp[%v], delay %v", addr, r.delay(addr))
}

func (r *reject) PacketConn(_ context.Context, addr netapi.Address) (net.PacketConn, error) {
	return nil, fmt.Errorf("blocked address udp[%v]. delay %v", addr, r.delay(addr))
}

func (r *reject) Ping(_ context.Context, addr netapi.Address) (uint64, error) {
	return 0, errors.New("blocked")
}

func (r *reject) Close() error { return nil }
