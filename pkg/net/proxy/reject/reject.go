package reject

import (
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

var _ proxy.Proxy = (*reject)(nil)

type reject struct {
	cache         *lru.LRU[string, object]
	max, internal int
}

type object struct {
	times int8
	time  time.Time
	delay time.Duration
}

var Default = NewReject(5, 15)

func NewReject(maxDelay, interval int) proxy.Proxy {
	return &reject{lru.NewLru[string, object](100, 0), maxDelay, interval}
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

func (r *reject) Conn(addr proxy.Address) (net.Conn, error) {
	return nil, fmt.Errorf("blocked address tcp[%v], delay %v", addr, r.delay(addr))
}

func (r *reject) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	return nil, fmt.Errorf("blocked address udp[%v]. delay %v", addr, r.delay(addr))
}
