package domain

import (
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/cache/badger"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type Trie[T comparable] interface {
	Insert(domain string, mark T)
	Search(domain netapi.Address) []T
	SearchString(domain string) []T
	Remove(domain string, mark T)
	Clear() error
	Close() error
}

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

func (d *Fqdn[T]) Search(domain netapi.Address) []T {
	return search(d.Root, newReader(domain.Hostname(), d.separate))
}

func (d *Fqdn[T]) SearchString(domain string) []T {
	return search(d.Root, newReader(domain, d.separate))
}

func (d *Fqdn[T]) Remove(domain string, mark T) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(domain) == 0 {
		return
	}

	r := newReader(domain, d.separate)
	remove(d.Root, r, mark)
}

func (d *Fqdn[T]) Clear() error {
	d.Root = &trie[T]{Child: map[string]*trie[T]{}}
	return nil
}

func (d *Fqdn[T]) SetSeparate(b byte) {
	d.separate = b
}

func (d *Fqdn[T]) Close() error {
	return nil
}

func NewTrie[T comparable]() *Fqdn[T] {
	return &Fqdn[T]{
		Root:     &trie[T]{Child: map[string]*trie[T]{}},
		separate: '.',
	}
}

type DiskFqdn[T comparable] struct {
	Root     *DiskTrie[T] `json:"root"`
	separate byte
	mu       sync.Mutex
}

func (d *DiskFqdn[T]) Insert(domain string, mark T) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(domain) == 0 {
		return
	}

	r := newReader(domain, d.separate)
	d.Root.Insert(r, mark)
}

func (d *DiskFqdn[T]) Search(domain netapi.Address) []T {
	return d.Root.Search(newReader(domain.Hostname(), d.separate))
}

func (d *DiskFqdn[T]) SearchString(domain string) []T {
	return d.Root.Search(newReader(domain, d.separate))
}

func (d *DiskFqdn[T]) Remove(domain string, mark T) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(domain) == 0 {
		return
	}

	r := newReader(domain, d.separate)
	d.Root.Remove(r, mark)
}

func (d *DiskFqdn[T]) SetSeparate(b byte) {
	d.separate = b
}

func (d *DiskFqdn[T]) Clear() error {
	return d.Root.Clear()
}

func (d *DiskFqdn[T]) Close() error {
	return d.Root.Close()
}

func NewDiskFqdn[T comparable](cache *badger.Cache, codec Codec[T]) *DiskFqdn[T] {
	return &DiskFqdn[T]{
		Root:     NewDiskTrie(cache, codec),
		separate: '.',
	}
}
