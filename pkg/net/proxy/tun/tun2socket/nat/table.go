package nat

import (
	"container/list"

	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	portBegin  = 30000
	portLength = 10240
)

var zeroTuple = Tuple{}

type Tuple struct {
	SourceAddr      tcpip.Address
	SourcePort      uint16
	DestinationAddr tcpip.Address
	DestinationPort uint16
}

type binding struct {
	tuple  Tuple
	offset uint16
}

type table struct {
	tuples    map[Tuple]*list.Element
	ports     [portLength]*list.Element
	available *list.List
}

func (t *table) tupleOf(port uint16) Tuple {
	offset := port - portBegin
	if offset > portLength {
		return zeroTuple
	}

	elm := t.ports[offset]

	t.available.MoveToFront(elm)

	return elm.Value.(*binding).tuple
}

func (t *table) portOf(tuple Tuple) uint16 {
	elm := t.tuples[tuple]
	if elm == nil {
		return 0
	}

	t.available.MoveToFront(elm)

	return portBegin + elm.Value.(*binding).offset
}

func (t *table) newConn(tuple Tuple) uint16 {
	elm := t.available.Back()
	b := elm.Value.(*binding)

	delete(t.tuples, b.tuple)
	t.tuples[tuple] = elm
	b.tuple = tuple

	t.available.MoveToFront(elm)

	return portBegin + b.offset
}

func newTable() *table {
	result := &table{
		tuples:    make(map[Tuple]*list.Element, portLength),
		ports:     [portLength]*list.Element{},
		available: list.New(),
	}

	for idx := range result.ports {
		result.ports[idx] = result.available.PushFront(&binding{
			tuple:  Tuple{},
			offset: uint16(idx),
		})
	}

	return result
}
