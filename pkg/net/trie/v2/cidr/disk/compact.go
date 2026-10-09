package disk

import (
	"container/heap"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

type segmentRecord[T comparable] struct {
	path   []uint8
	values []T
}

type segmentFrame struct {
	id      uint64
	next    uint64
	entered bool
	emitted int
	pathLen int
}

type segmentIterator[T comparable] struct {
	segment *segment[T]
	stack   []segmentFrame
	path    []uint8
}

func newSegmentIterator[T comparable](segment *segment[T]) *segmentIterator[T] {
	return &segmentIterator[T]{segment: segment, stack: []segmentFrame{{id: segment.rootID}}}
}

// next returns a path borrowed until the next call on this iterator.
func (it *segmentIterator[T]) next() (segmentRecord[T], bool, error) {
	for len(it.stack) != 0 {
		top := &it.stack[len(it.stack)-1]
		node, ok := it.segment.node(top.id)
		if !ok || top.next > 2 || len(it.path) > 129 {
			return segmentRecord[T]{}, false, errors.New("invalid disk CIDR iterator node")
		}
		if !top.entered {
			if top.emitted < len(it.path)-1 {
				top.emitted++
				return segmentRecord[T]{path: it.path[:top.emitted]}, true, nil
			}
			top.entered = true
			return segmentRecord[T]{
				path:   it.path,
				values: it.segment.valuesNode(top.id),
			}, true, nil
		}
		if top.next < 2 {
			branch := top.next
			top.next++
			child := node.left
			if branch == 1 {
				child = node.right
			}
			if child == absentChild {
				continue
			}
			id, skip, prefix, ok := it.segment.decodeLink(child, top.id)
			if !ok {
				return segmentRecord[T]{}, false, errors.New("invalid CIDR child link")
			}
			parentLen := len(it.path)
			expectedDepth := parentLen
			if expectedDepth+skip > 128 || (parentLen != 0 && it.path[0] == 0 && expectedDepth+skip > 32) {
				return segmentRecord[T]{}, false, errors.New("CIDR jump exceeds address width")
			}
			it.path = append(it.path, uint8(branch))
			for depth := expectedDepth; depth < expectedDepth+skip; depth++ {
				it.path = append(it.path, bitAt(prefix[:], depth))
			}
			it.stack = append(it.stack, segmentFrame{id: id, emitted: parentLen, pathLen: parentLen})
			continue
		}
		parentLen := top.pathLen
		it.stack = it.stack[:len(it.stack)-1]
		it.path = it.path[:parentLen]
	}
	return segmentRecord[T]{}, false, nil
}

type mergeItem[T comparable] struct {
	iterator *segmentIterator[T]
	record   segmentRecord[T]
	order    int
}

type mergeHeap[T comparable] []*mergeItem[T]

func (h mergeHeap[T]) Len() int { return len(h) }

func (h mergeHeap[T]) Less(i, j int) bool {
	if comparePath(h[i].record.path, h[j].record.path) != 0 {
		return comparePath(h[i].record.path, h[j].record.path) < 0
	}
	return h[i].order < h[j].order
}

func (h mergeHeap[T]) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *mergeHeap[T]) Push(value any) { *h = append(*h, value.(*mergeItem[T])) }

func (h *mergeHeap[T]) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}

func comparePath(a, b []uint8) int {
	for index := 0; index < len(a) && index < len(b); index++ {
		if a[index] < b[index] {
			return -1
		}
		if a[index] > b[index] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

func commonPath(a, b []uint8) int {
	length := min(len(b), len(a))
	for index := range length {
		if a[index] != b[index] {
			return index
		}
	}
	return length
}

// forEachMerged performs a k-way merge while retaining only the next record
// from each input segment.
func forEachMerged[T comparable](segments []*segment[T], fn func([]uint8, []T) error) error {
	queue := make(mergeHeap[T], 0, len(segments))
	for index, segment := range segments {
		iterator := newSegmentIterator(segment)
		record, ok, err := iterator.next()
		if err != nil {
			return err
		}
		if ok {
			heap.Push(&queue, &mergeItem[T]{iterator: iterator, record: record, order: index})
		}
	}

	for queue.Len() != 0 {
		first := heap.Pop(&queue).(*mergeItem[T])
		path := first.record.path
		values := first.record.values
		items := []*mergeItem[T]{first}
		for queue.Len() != 0 && comparePath(queue[0].record.path, path) == 0 {
			item := heap.Pop(&queue).(*mergeItem[T])
			values = appendUnique(values, item.record.values...)
			items = append(items, item)
		}
		if err := fn(path, values); err != nil {
			return err
		}
		for _, item := range items {
			record, ok, err := item.iterator.next()
			if err != nil {
				return err
			}
			if ok {
				item.record = record
				heap.Push(&queue, item)
			}
		}
	}
	return nil
}

func compactSegments[T comparable](path string, segments []*segment[T], c codec.Codec[T]) (*segment[T], error) {
	return writeCompressedSegment(path, c, func(yield func([]uint8, []T) error) error {
		return forEachMerged(segments, yield)
	})
}

func (t *Trie[T]) compactOldestLocked(count int) error {
	if count < 2 || len(t.segments) < count {
		return nil
	}
	old := slices.Clone(t.segments[:count])
	finalPath := old[0].path
	tmpPath := filepath.Join(t.dir, fmt.Sprintf(".compact-%020d.cidr", t.nextID))
	merged, err := compactSegments(tmpPath, old, t.codec)
	if err != nil {
		return err
	}
	if err := merged.close(); err != nil {
		return err
	}
	for _, segment := range old {
		if err := segment.close(); err != nil {
			return err
		}
		if err := os.Remove(segment.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return err
	}
	newSegment, err := openSegment[T](finalPath, t.codec)
	if err != nil {
		return err
	}
	t.segments = append([]*segment[T]{newSegment}, t.segments[count:]...)
	return nil
}
