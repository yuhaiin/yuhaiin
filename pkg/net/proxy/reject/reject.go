package reject

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

var _ netapi.Proxy = (*reject)(nil)

type rejectImmediately struct{ netapi.EmptyDispatch }

func (rejectImmediately) Conn(_ context.Context, addr netapi.Address) (net.Conn, error) {
	return nil, netapi.NewBlockError(statistic.Type_tcp, addr.Hostname())
}
func (rejectImmediately) PacketConn(_ context.Context, addr netapi.Address) (net.PacketConn, error) {
	return nil, netapi.NewBlockError(statistic.Type_udp, addr.Hostname())
}

type reject struct {
	cache         *lru.LRU[string, object]
	max, internal int
	netapi.EmptyDispatch
}

type object struct {
	times int8
	time  time.Time
	delay time.Duration
}

func init() {
	point.RegisterProtocol(func(*protocol.Protocol_Reject) point.WrapProxy {
		return func(netapi.Proxy) (netapi.Proxy, error) { return Default, nil }
	})
}

var Default = rejectImmediately{}

func NewReject(maxDelay, interval int) netapi.Proxy {
	return &reject{cache: lru.NewLru(lru.WithCapacity[string, object](100)), max: maxDelay, internal: interval}
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
	r.cache.Add(addr.Hostname(), object{z.times, time.Now(), z.delay})
	return z.delay
}

func (r *reject) Conn(_ context.Context, addr netapi.Address) (net.Conn, error) {
	return nil, fmt.Errorf("blocked address tcp[%v], delay %v", addr, r.delay(addr))
}

func (r *reject) PacketConn(_ context.Context, addr netapi.Address) (net.PacketConn, error) {
	return nil, fmt.Errorf("blocked address udp[%v]. delay %v", addr, r.delay(addr))
}
