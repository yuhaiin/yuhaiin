package domain

import (
	"errors"
	"iter"
	"slices"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/cache/pebble"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

type DiskPebbleTrie[T comparable] struct {
	root   *pebble.Cache
	closed atomic.Bool
	codec  codec.Codec[T]
}

func NewDiskPebbleTrie[T comparable](root *pebble.Cache, codec codec.Codec[T]) *DiskPebbleTrie[T] {
	return &DiskPebbleTrie[T]{root: root, codec: codec}
}

func (dt *DiskPebbleTrie[T]) child(node *pebble.Cache, s string, insert bool) (*pebble.Cache, bool) {
	if insert {
		return node.NewCache(s).(*pebble.Cache), true
	} else {
		if !node.CacheExists(s) {
			return nil, false
		}
		return node.NewCache(s).(*pebble.Cache), true
	}
}

func (dt *DiskPebbleTrie[T]) getValue(node cache.Geter) []T {
	data, err := node.Get(valKey)
	if err != nil {
		return nil
	}

	return dt.decodeValue(data)
}

func (dt *DiskPebbleTrie[T]) decodeValue(data []byte) []T {
	if len(data) == 0 {
		return nil
	}
	var res []T
	var err error
	if res, err = dt.codec.Decode(data); err != nil {
		log.Warn("disktrie decode failed", "err", err)
	}

	return res
}

func (dt *DiskPebbleTrie[T]) setValue(node *pebble.Cache, vals []T) error {
	if len(vals) == 0 {
		return node.Delete(valKey)
	}

	bytes, err := dt.encodeValue(vals)
	if err != nil {
		return err
	}

	return node.Put(valKey, bytes)
}

func (dt *DiskPebbleTrie[T]) encodeValue(vals []T) ([]byte, error) {
	if len(vals) == 0 {
		return nil, nil
	}
	return dt.codec.Encode(vals)
}

func (dt *DiskPebbleTrie[T]) Insert(z *fqdnReader, mark T) error {
	if dt.closed.Load() {
		return errors.New("trie is closed")
	}

	key := z.array(nil)

	node := dt.root.NewCache(key...).(*pebble.Cache)

	vals := dt.getValue(node)
	if !slices.Contains(vals, mark) {
		return dt.setValue(node, append(vals, mark))
	}
	return nil
}

func (dt *DiskPebbleTrie[T]) Batch(items iter.Seq2[*fqdnReader, T]) error {
	if dt.closed.Load() {
		return errors.New("trie is closed")
	}

	next, stop := iter.Pull2(items)
	defer stop()

	var (
		keyBuf   []string
		pendingK []string
		pendingV []byte
		done     bool
	)

	for !done {
		err := dt.root.Batch(func(txn cache.Batch) error {
			bt := txn.(*pebble.Batch)

			if pendingK != nil && pendingV != nil {
				if err := bt.PutToCache(pendingK, valKey, pendingV); err != nil {
					return err
				}
				pendingK = nil
				pendingV = nil
			}

			for range 90 {
				k, v, ok := next()
				if !ok {
					done = true
					return nil
				}

				keyBuf = k.array(keyBuf[:0])

				data, _ := bt.GetFromCache(keyBuf, valKey)
				vals := dt.decodeValue(data)

				if slices.Contains(vals, v) {
					continue
				}

				ev, err := dt.encodeValue(append(vals, v))
				if err != nil {
					return err
				}

				if err := bt.PutToCache(keyBuf, valKey, ev); err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (dt *DiskPebbleTrie[T]) Search(domain *fqdnReader) []T {
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

func (dt *DiskPebbleTrie[T]) Clear() error {
	if dt.closed.Load() {
		return errors.New("trie is closed")
	}
	start := []byte{0x00}
	end := []byte{0xff, 0xff, 0xff, 0xff}

	return dt.root.Pebble().DeleteRange(start, end, nil)
}

func (dt *DiskPebbleTrie[T]) Close() error {
	dt.closed.CompareAndSwap(false, true)
	return nil
}

func (dt *DiskPebbleTrie[T]) Remove(domain *fqdnReader, mark T) error {
	if dt.closed.Load() {
		return errors.New("trie is closed")
	}

	type step struct {
		node *pebble.Cache
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

func (dt *DiskPebbleTrie[T]) Dir() string {
	return dt.root.Dir()
}
