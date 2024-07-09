package nat

import (
	"math"
	"sync"

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
	v6 *table
	v4 *table
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
	lru *lru.ReverseSyncLru[Tuple, uint16]

	mu    sync.Mutex
	index uint16
}

func newTableBase() *table {
	return &table{
		lru: lru.NewSyncReverseLru(lru.WithCapacity[Tuple, uint16](math.MaxUint16 - 10001)),
	}
}

func (t *table) tupleOf(port uint16, _ bool) Tuple {
	p, _ := t.lru.ReverseLoad(port)
	return p
}

func (t *table) portOf(tuple Tuple) uint16 {
	p, _ := t.lru.Load(tuple)
	return p
}

func (t *table) newConn(tuple Tuple) uint16 {
	t.mu.Lock()
	newPort, ok := t.lru.LastPopValue()
	if !ok {
		if t.index == 0 {
			newPort = 10000
		} else {
			newPort = t.index
		}
		t.index = newPort + 1
	}
	t.lru.Add(tuple, newPort)
	defer t.mu.Unlock()

	return newPort
}

func newTable() *tableSplit {
	return &tableSplit{
		v6: newTableBase(),
		v4: newTableBase(),
	}
}
