package domain

import (
	"bytes"
	"encoding/gob"
	"errors"
	"slices"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/cache/badger"
	"github.com/Asutorufa/yuhaiin/pkg/log"
)

type Codec[T comparable] interface {
	Encode([]T) ([]byte, error)
	Decode([]byte) ([]T, error)
}

type GobCodec[T comparable] struct{}

func (GobCodec[T]) Encode(v []T) ([]byte, error) {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(v)
	return buf.Bytes(), err
}

func (GobCodec[T]) Decode(b []byte) ([]T, error) {
	var v []T
	err := gob.NewDecoder(bytes.NewReader(b)).Decode(&v)
	return v, err
}

var valKey = []byte{0x0, 'V', 0x0, 0b10101010}

type DiskTrie[T comparable] struct {
	root   *badger.Cache
	closed atomic.Bool
	codec  Codec[T]
}

func NewDiskTrie[T comparable](root *badger.Cache) *DiskTrie[T] {
	return &DiskTrie[T]{root: root, codec: GobCodec[T]{}}
}

func (dt *DiskTrie[T]) child(node *badger.Cache, s string, insert bool) (*badger.Cache, bool) {
	if insert {
		return node.NewCache(s).(*badger.Cache), true
	} else {
		if !node.CacheExists(s) {
			return nil, false
		}
		return node.NewCache(s).(*badger.Cache), true
	}
}

func (dt *DiskTrie[T]) getValue(node *badger.Cache) []T {
	data, err := node.Get(valKey)
	if err != nil || len(data) == 0 {
		return nil
	}
	var res []T
	if res, err = dt.codec.Decode(data); err != nil {
		log.Warn("disktrie decode failed", "err", err)
	}

	return res
}

func (dt *DiskTrie[T]) setValue(node *badger.Cache, vals []T) error {
	if len(vals) == 0 {
		return nil
	}

	bytes, err := dt.codec.Encode(vals)
	if err != nil {
		return err
	}

	return node.Put(valKey, bytes)
}

func (dt *DiskTrie[T]) Insert(z *fqdnReader, mark T) error {
	if dt.closed.Load() {
		return errors.New("trie is closed")
	}

	key := []string{}

	for ; z.hasNext(); z.next() {
		key = append(key, z.str())
	}

	node := dt.root.NewCache(key...).(*badger.Cache)

	vals := dt.getValue(node)
	if !slices.Contains(vals, mark) {
		return dt.setValue(node, append(vals, mark))
	}
	return nil
}

func (dt *DiskTrie[T]) Search(domain *fqdnReader) []T {
	if dt.closed.Load() {
		return nil
	}

	var res []T
	root := dt.root

	r, ok := dt.child(root, domain.str(), false)
	if ok {
		root = r
		goto _second
	}

	root, ok = dt.child(root, "*", false)
	if !ok {
		return res
	}
	for ; domain.hasNext(); domain.next() {
		if r, ok = dt.child(root, domain.str(), false); ok {
			root = r
			goto _second
		}
	}

	return res

_second:

	for domain.next() {
		if r, ok := dt.child(root, "*", false); ok {
			res = append(res, dt.getValue(r)...)
		}
		root, ok = dt.child(root, domain.str(), false)
		if !ok {
			return res
		}
	}

	res = append(res, dt.getValue(root)...)

	if r, ok := dt.child(root, "*", false); ok {
		res = append(res, dt.getValue(r)...)
	}

	return res
}

func (dt *DiskTrie[T]) Clear() error {
	if dt.closed.Load() {
		return errors.New("trie is closed")
	}

	return dt.root.Badger().DropAll()
}

func (dt *DiskTrie[T]) Close() error {
	dt.closed.CompareAndSwap(false, true)
	return nil
}

func (dt *DiskTrie[T]) Remove(domain *fqdnReader, mark T) error {
	if dt.closed.Load() {
		return errors.New("trie is closed")
	}

	type step struct {
		node *badger.Cache
		part string
	}

	node := dt.root
	nodes := []step{{node: node, part: ""}}

	for domain.hasNext() {
		part := domain.str()
		z, ok := dt.child(node, part, false)
		if !ok {
			return nil
		}

		node = z
		nodes = append(nodes, step{node: node, part: part})
		domain.next()
	}

	vals := dt.getValue(node)
	if index := slices.Index(vals, mark); index != -1 {
		vals = append(vals[:index], vals[index+1:]...)
		if err := dt.setValue(node, vals); err != nil {
			return err
		}
	}

	for i := len(nodes) - 1; i >= 1; i-- {
		childStep := nodes[i]

		childVals := dt.getValue(childStep.node)

		if len(childVals) == 0 {
			// childStep.node.Delete(valKey)
		} else {
			break
		}
	}

	return nil
}
