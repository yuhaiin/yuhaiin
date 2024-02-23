package domain

import (
	"encoding/json"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type Fqdn[T any] struct {
	Root         *trie[T] `json:"root"`          // for example.com, example.*
	WildcardRoot *trie[T] `json:"wildcard_root"` // for *.example.com, *.example.*
	mu           sync.Mutex
}

func (d *Fqdn[T]) Insert(domain string, mark T) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(domain) == 0 {
		return
	}

	r := newReader(domain)
	if domain[0] == '*' {
		insert(d.WildcardRoot, r, mark)
	} else {
		insert(d.Root, r, mark)
	}
}

func (d *Fqdn[T]) Search(domain netapi.Address) (mark T, ok bool) {
	r := newReader(domain.Hostname())

	mark, ok = search(d.Root, r)
	if ok {
		return
	}

	r.reset()

	return search(d.WildcardRoot, r)
}
func (d *Fqdn[T]) SearchString(domain string) (mark T, ok bool) {
	r := newReader(domain)

	mark, ok = search(d.Root, r)
	if ok {
		return
	}

	r.reset()

	return search(d.WildcardRoot, r)
}

func (d *Fqdn[T]) Remove(domain string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(domain) == 0 {
		return
	}

	r := newReader(domain)
	if domain[0] == '*' {
		remove(d.WildcardRoot, r)
	} else {
		remove(d.Root, r)
	}
}

func (d *Fqdn[T]) Marshal() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

func (d *Fqdn[T]) Clear() error {
	d.Root = &trie[T]{Child: map[string]*trie[T]{}}
	d.WildcardRoot = &trie[T]{Child: map[string]*trie[T]{}}
	return nil
}

func NewDomainMapper[T any]() *Fqdn[T] {
	return &Fqdn[T]{
		Root:         &trie[T]{Child: map[string]*trie[T]{}},
		WildcardRoot: &trie[T]{Child: map[string]*trie[T]{}},
	}
}
