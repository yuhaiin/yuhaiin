package reject

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

var _ proxy.Proxy = (*reject)(nil)

type rejectImmediately struct{ proxy.EmptyDispatch }

func (rejectImmediately) Conn(_ context.Context, addr proxy.Address) (net.Conn, error) {
	return nil, proxy.NewBlockError(statistic.Type_tcp, addr.Hostname())
}
func (rejectImmediately) PacketConn(_ context.Context, addr proxy.Address) (net.PacketConn, error) {
	return nil, proxy.NewBlockError(statistic.Type_udp, addr.Hostname())
}

type reject struct {
	cache         *lru.LRU[string, object]
	max, internal int
	proxy.EmptyDispatch
}

type object struct {
	times int8
	time  time.Time
	delay time.Duration
}

var Default = rejectImmediately{}

func NewReject(maxDelay, interval int) proxy.Proxy {
	return &reject{cache: lru.NewLru(lru.WithCapacity[string, object](100)), max: maxDelay, internal: interval}
}

func (r *reject) delay(addr proxy.Address) time.Duration {
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

func (r *reject) Conn(_ context.Context, addr proxy.Address) (net.Conn, error) {
	return nil, fmt.Errorf("blocked address tcp[%v], delay %v", addr, r.delay(addr))
}

func (r *reject) PacketConn(_ context.Context, addr proxy.Address) (net.PacketConn, error) {
	return nil, fmt.Errorf("blocked address udp[%v]. delay %v", addr, r.delay(addr))
}
