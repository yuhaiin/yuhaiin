package nat

import (
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"gvisor.dev/gvisor/pkg/tcpip"
)

var zeroTuple = Tuple{}

type Tuple struct {
	SourceAddr      tcpip.Address
	SourcePort      uint16
	DestinationAddr tcpip.Address
	DestinationPort uint16
}

type tableSplit struct {
	v6 table
	v4 table
}

func (t *tableSplit) tupleOf(port uint16, ipv6 bool) Tuple {
	if ipv6 {
		return t.v6.tupleOf(port, true)
	}

	return t.v4.tupleOf(port, false)
}

func (t *tableSplit) portOf(tuple Tuple) uint16 {
	if tuple.SourceAddr.Len() == 16 {
		return t.v6.portOf(tuple)
	}

	return t.v4.portOf(tuple)
}

func (t *tableSplit) newConn(tuple Tuple) uint16 {
	if tuple.SourceAddr.Len() == 16 {
		return t.v6.newConn(tuple)
	}

	return t.v4.newConn(tuple)
}

type table struct {
	tuples syncmap.SyncMap[Tuple, uint16]
	ports  syncmap.SyncMap[uint16, Tuple]

	mu    sync.Mutex
	index uint16
}

func (t *table) tupleOf(port uint16, _ bool) Tuple {
	p, _ := t.ports.Load(port)
	return p
}

func (t *table) portOf(tuple Tuple) uint16 {
	p, _ := t.tuples.Load(tuple)
	return p
}

func (t *table) newConn(tuple Tuple) uint16 {
	t.mu.Lock()
	var newPort uint16
	if t.index == 0 {
		newPort = 10000
	} else {
		newPort = t.index
	}
	t.index = newPort + 1
	t.ports.Store(newPort, tuple)
	t.tuples.Store(tuple, newPort)
	defer t.mu.Unlock()

	return newPort
}

func newTable() *tableSplit { return &tableSplit{} }
