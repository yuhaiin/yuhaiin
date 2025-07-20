package tun2socket

import (
	"math"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
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
		return t.v6.tupleOf(port)
	}

	return t.v4.tupleOf(port)
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
	set   *set.Set[uint16]
	mu    sync.Mutex
	index uint16
}

var defaultTableSize = math.MaxUint16 - 10001

func newTableBase(expire time.Duration) *table {
	set := set.NewSet[uint16]()
	return &table{
		lru: lru.NewSyncReverseLru(
			lru.WithLruOptions(
				lru.WithCapacity[Tuple, uint16](uint(defaultTableSize)),
				lru.WithDefaultTimeout[Tuple, uint16](expire),
				lru.WithOnRemove(func(t Tuple, p uint16) { set.Push(p) }),
			),
			lru.WithOnValueChanged[Tuple](func(old, new uint16) {
				if old != new {
					set.Push(old)
				}
			}),
		),
		set: set,
	}
}

func (t *table) tupleOf(port uint16) Tuple {
	// TODO maybe we do not need refresh here
	// because [table.portOf] also refresh
	p, _ := t.lru.ReverseLoadRefreshExpire(port)
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
		if t.index < 10000 {
			t.index = 10000
		}

		start := t.index
		t.index++
		for ; t.index != start; t.index++ {
			if t.index < 10000 {
				t.index = 10000
				continue
			}

			if ok := t.lru.ValueExist(t.index); !ok {
				newPort = t.index
				t.index++
				break
			}
		}
	}
	if newPort != 0 {
		t.lru.Add(tuple, newPort)
	}
	t.mu.Unlock()

	return newPort
}

func (t *table) ClearExpired() { t.lru.ClearExpired() }

var defaultExpire = 5 * time.Minute

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
