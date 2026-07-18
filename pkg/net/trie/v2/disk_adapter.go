package trie

import (
	"iter"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/disk"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/domain"
)

type diskDomain[T comparable] struct {
	trie *disk.Trie[T]
}

// newDiskDomain adapts the persistent Trie to the domain.Trie interface used
// by the route package. The adapter intentionally keeps lifecycle operations
// delegated to the disk Trie so there is one owner for file handles.
func newDiskDomain[T comparable](trie *disk.Trie[T]) domain.Trie[T] {
	return &diskDomain[T]{trie: trie}
}

func (d *diskDomain[T]) Insert(value string, mark T) {
	_ = d.trie.Insert(value, mark)
}

func (d *diskDomain[T]) Batch(values iter.Seq2[string, T]) error {
	return d.trie.Batch(values)
}

func (d *diskDomain[T]) Search(address netapi.Address) []T {
	return d.trie.Search(address.Hostname())
}

func (d *diskDomain[T]) SearchString(value string) []T {
	return d.trie.Search(value)
}

func (d *diskDomain[T]) Remove(value string, mark T) {
	_ = d.trie.Remove(value, mark)
}

func (d *diskDomain[T]) Clear() error {
	return d.trie.Clear()
}

func (d *diskDomain[T]) SetSeparate(separate byte) {
	d.trie.SetSeparate(separate)
}

func (d *diskDomain[T]) Close() error {
	return d.trie.Close()
}
