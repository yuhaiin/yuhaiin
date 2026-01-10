package domain

import (
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/cache/badger"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type Fqdn[T comparable] struct {
	Root     *DiskTrie[T] `json:"root"`
	separate byte
	mu       sync.Mutex
}

func (d *Fqdn[T]) Insert(domain string, mark T) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(domain) == 0 {
		return
	}

	r := newReader(domain, d.separate)
	d.Root.Insert(r, mark)
}

func (d *Fqdn[T]) Search(domain netapi.Address) []T {
	return d.Root.Search(newReader(domain.Hostname(), d.separate))
}

func (d *Fqdn[T]) SearchString(domain string) []T {
	return d.Root.Search(newReader(domain, d.separate))
}

func (d *Fqdn[T]) Remove(domain string, mark T) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(domain) == 0 {
		return
	}

	r := newReader(domain, d.separate)
	d.Root.Remove(r, mark)
}

func (d *Fqdn[T]) SetSeparate(b byte) {
	d.separate = b
}

func (d *Fqdn[T]) Clear() error {
	return d.Root.Clear()
}

func (d *Fqdn[T]) Close() error {
	return d.Root.Close()
}

func NewTrie[T comparable](path string) *Fqdn[T] {
	cache, err := badger.New(path)
	if err != nil {
		panic(err)
	}
	return &Fqdn[T]{
		Root:     &DiskTrie[T]{root: cache},
		separate: '.',
	}
}
