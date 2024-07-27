package nat

import (
	"math"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/list"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"gvisor.dev/gvisor/pkg/tcpip"
)

var zeroTuple = Tuple{}

type Tuple struct {
	SourceAddr      tcpip.Address
	DestinationAddr tcpip.Address
	SourcePort      uint16
	DestinationPort uint16
}

type tableSplit struct {
	v6    *table
	v4    *table
	timer *time.Timer
}

func (t *tableSplit) tupleOf(port uint16, ipv6 bool) Tuple {
	if ipv6 {
		return t.v6.tupleOf(port, true)
	}

	return t.v4.tupleOf(port, false)
}

func (t *tableSplit) portOf(tuple Tuple) uint16 {
	if tuple.SourceAddr.Len() == 16 {
		if port := t.v6.portOf(tuple); port != 0 {
			return port
		}
		return t.v6.newConn(tuple)
	}

	if port := t.v4.portOf(tuple); port != 0 {
		return port
	}
	return t.v4.newConn(tuple)
}

type table struct {
	lru   *lru.ReverseSyncLru[Tuple, uint16]
	set   *list.Set[uint16]
	mu    sync.Mutex
	index uint16
}

var defaultTableSize = math.MaxUint16 - 10001

func newTableBase(expire time.Duration) *table {
	set := list.NewSet[uint16]()
	return &table{
		lru: lru.NewSyncReverseLru(
			lru.WithCapacity[Tuple, uint16](uint(defaultTableSize)),
			lru.WithExpireTimeout[Tuple, uint16](expire),
			lru.WithOnRemove(func(t Tuple, p uint16) { set.Push(p) }),
		),
		set: set,
	}
}

func (t *table) tupleOf(port uint16, _ bool) Tuple {
	p, _ := t.lru.ReverseLoad(port)
	return p
}

func (t *table) portOf(tuple Tuple) uint16 {
	p, _ := t.lru.LoadRefreshExpire(tuple)
	return p
}

func (t *table) newConn(tuple Tuple) uint16 {
	t.mu.Lock()
	newPort, ok := t.set.Pop()
	if !ok {
		if t.index == 0 {
			newPort = 10000
		} else {
			newPort = t.index
		}
		t.index = newPort + 1
	}
	t.lru.Add(tuple, newPort)
	t.mu.Unlock()

	return newPort
}

func (t *table) ClearExpired() { t.lru.ClearExpired() }

var defaultExpire = 3 * time.Minute

func newTable() *tableSplit {
	t := &tableSplit{
		v6: newTableBase(defaultExpire),
		v4: newTableBase(defaultExpire),
	}

	t.timer = time.AfterFunc(defaultExpire, func() {
		t.v6.ClearExpired()
		t.v4.ClearExpired()

		t.timer.Reset(defaultExpire)
	})

	return t
}

func (t *tableSplit) Close() error {
	t.timer.Stop()
	return nil
}
