package domain

import (
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

type Fqdn[T comparable] struct {
	Root     *trie[T] `json:"root"`
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
	insert(d.Root, r, mark)
}

func (d *Fqdn[T]) Search(domain netapi.Address) *set.Set[T] {
	return search(d.Root, newReader(domain.Hostname(), d.separate))
}

func (d *Fqdn[T]) SearchString(domain string) *set.Set[T] {
	return search(d.Root, newReader(domain, d.separate))
}

func (d *Fqdn[T]) Remove(domain string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(domain) == 0 {
		return
	}

	r := newReader(domain, d.separate)
	remove(d.Root, r, *new(T))
}

func (d *Fqdn[T]) Clear() error {
	d.Root = &trie[T]{Child: map[string]*trie[T]{}}
	return nil
}

func (d *Fqdn[T]) SetSeparate(b byte) {
	d.separate = b
}

func NewTrie[T comparable]() *Fqdn[T] {
	return &Fqdn[T]{
		Root:     &trie[T]{Child: map[string]*trie[T]{}},
		separate: '.',
	}
}
