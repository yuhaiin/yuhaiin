package disk

import (
	"container/heap"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
}

type segmentIterator[T comparable] struct {
	segment *segment[T]
	stack   []segmentFrame
	path    []uint8
}

func newSegmentIterator[T comparable](segment *segment[T]) *segmentIterator[T] {
	return &segmentIterator[T]{segment: segment, stack: []segmentFrame{{id: 0}}}
}

func (it *segmentIterator[T]) next() (segmentRecord[T], bool, error) {
	for len(it.stack) != 0 {
		top := &it.stack[len(it.stack)-1]
		node, ok := it.segment.node(top.id)
		if !ok || top.next > 2 {
			return segmentRecord[T]{}, false, errors.New("invalid disk CIDR iterator node")
		}
		if !top.entered {
			top.entered = true
			return segmentRecord[T]{
				path:   append([]uint8(nil), it.path...),
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
			it.path = append(it.path, uint8(branch))
			it.stack = append(it.stack, segmentFrame{id: child})
			continue
		}
		it.stack = it.stack[:len(it.stack)-1]
		if len(it.path) != 0 {
			it.path = it.path[:len(it.path)-1]
		}
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
	length := len(a)
	if len(b) < length {
		length = len(b)
	}
	for index := 0; index < length; index++ {
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
		values := append([]T(nil), first.record.values...)
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

type planNode struct {
	childMask uint8
	valueOff  uint64
	valueLen  uint64
}

type planState struct {
	offset    int64
	childMask uint8
	valueOff  uint64
	valueLen  uint64
}

type compactionStats struct {
	nodes  uint64
	values uint64
}

type outputFrame struct {
	id        uint64
	left      uint64
	right     uint64
	valueOff  uint64
	valueLen  uint64
	childMask uint8
}

const planNodeSize = 32

func writePlanNode(file *os.File, offset int64, node planNode) error {
	data := make([]byte, planNodeSize)
	data[0] = node.childMask
	binary.LittleEndian.PutUint64(data[8:], node.valueOff)
	binary.LittleEndian.PutUint64(data[16:], node.valueLen)
	_, err := file.WriteAt(data, offset)
	return err
}

func readPlanNode(file *os.File, offset int64) (planNode, error) {
	data := make([]byte, planNodeSize)
	n, err := file.ReadAt(data, offset)
	if err != nil {
		return planNode{}, err
	}
	if n != len(data) {
		return planNode{}, errors.New("short disk CIDR compaction plan")
	}
	return planNode{
		childMask: data[0],
		valueOff:  binary.LittleEndian.Uint64(data[8:]),
		valueLen:  binary.LittleEndian.Uint64(data[16:]),
	}, nil
}

func (state planState) node() planNode {
	return planNode{childMask: state.childMask, valueOff: state.valueOff, valueLen: state.valueLen}
}

func buildCompactionPlan[T comparable](dir string, segments []*segment[T], c codec.Codec[T]) (string, compactionStats, error) {
	file, err := os.CreateTemp(dir, ".cidr-compaction-plan-*")
	if err != nil {
		return "", compactionStats{}, err
	}
	path := file.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(path)
		}
	}()

	if err := writePlanNode(file, 0, planNode{}); err != nil {
		_ = file.Close()
		return "", compactionStats{}, err
	}
	stats := compactionStats{nodes: 1}
	stack := []planState{{offset: 0}}
	var previous []uint8
	err = forEachMerged(segments, func(path []uint8, values []T) error {
		common := commonPath(previous, path)
		for len(stack)-1 > common {
			stack = stack[:len(stack)-1]
		}
		if len(path) > common+1 {
			return errors.New("disk CIDR compaction stream skipped a path node")
		}
		if len(path) == common+1 {
			parent := &stack[len(stack)-1]
			parent.childMask |= 1 << path[common]
			if err := writePlanNode(file, parent.offset, parent.node()); err != nil {
				return err
			}
			state := planState{offset: int64(stats.nodes) * planNodeSize}
			stack = append(stack, state)
			stats.nodes++
			if err := writePlanNode(file, state.offset, state.node()); err != nil {
				return err
			}
		}

		encoded, err := encodeValues(c, values)
		if err != nil {
			return err
		}
		current := &stack[len(stack)-1]
		current.valueOff = stats.values
		current.valueLen = uint64(len(encoded))
		if err := writePlanNode(file, current.offset, current.node()); err != nil {
			return err
		}
		stats.values += uint64(len(encoded))
		previous = append(previous[:0], path...)
		return nil
	})
	if err != nil {
		_ = file.Close()
		return "", compactionStats{}, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", compactionStats{}, err
	}
	if err := file.Close(); err != nil {
		return "", compactionStats{}, err
	}
	keep = true
	return path, stats, nil
}

func compactSegments[T comparable](path string, segments []*segment[T], c codec.Codec[T]) (*segment[T], error) {
	planPath, stats, err := buildCompactionPlan(filepath.Dir(path), segments, c)
	if err != nil {
		return nil, err
	}
	defer os.Remove(planPath)

	tmp, err := os.CreateTemp(filepath.Dir(path), ".cidr-compacted-segment-*")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()

	nodeOff := uint64(segmentHeaderSize)
	valueOff := nodeOff + stats.nodes*segmentNodeSize
	total := valueOff + stats.values
	if err := tmp.Truncate(int64(total)); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := writeSegmentHeaderAt(tmp, nodeOff, stats.nodes, valueOff, stats.values); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	plan, err := os.Open(planPath)
	if err != nil {
		_ = tmp.Close()
		return nil, err
	}
	closePlan := true
	defer func() {
		if closePlan {
			_ = plan.Close()
		}
	}()

	stack := make([]outputFrame, 0, 128)
	var previous []uint8
	var nodeID uint64
	err = forEachMerged(segments, func(path []uint8, values []T) error {
		common := commonPath(previous, path)
		for len(stack)-1 > common {
			stack = stack[:len(stack)-1]
		}
		if len(path) > common+1 {
			return errors.New("disk CIDR compaction output skipped a path node")
		}
		if len(path) == common+1 {
			parent := &stack[len(stack)-1]
			if path[common] == 0 {
				parent.left = nodeID
			} else {
				parent.right = nodeID
			}
			if err := writeOutputNode(tmp, parent); err != nil {
				return err
			}
		}

		planned, err := readPlanNode(plan, int64(nodeID)*planNodeSize)
		if err != nil {
			return err
		}
		if nodeID != 0 && len(path) != common+1 {
			return errors.New("disk CIDR compaction duplicate path")
		}
		frame := outputFrame{
			id:        nodeID,
			left:      absentChild,
			right:     absentChild,
			valueOff:  planned.valueOff,
			valueLen:  planned.valueLen,
			childMask: planned.childMask,
		}
		if err := writeOutputNode(tmp, &frame); err != nil {
			return err
		}
		if planned.valueLen != 0 {
			encoded, err := encodeValues(c, values)
			if err != nil {
				return err
			}
			if uint64(len(encoded)) != planned.valueLen {
				return errors.New("disk CIDR compaction value size changed")
			}
			if _, err := tmp.WriteAt(encoded, int64(valueOff+planned.valueOff)); err != nil {
				return err
			}
		}
		stack = append(stack, frame)
		nodeID++
		previous = append(previous[:0], path...)
		return nil
	})
	if err != nil {
		_ = plan.Close()
		closePlan = false
		_ = tmp.Close()
		return nil, err
	}
	if err := plan.Close(); err != nil {
		closePlan = false
		_ = tmp.Close()
		return nil, err
	}
	closePlan = false
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return nil, err
	}
	keep = true
	return openSegment[T](path, c)
}

func writeSegmentHeaderAt(file *os.File, nodeOff, nodeCount, valueOff, valueLen uint64) error {
	header := make([]byte, segmentHeaderSize)
	copy(header, segmentMagic)
	binary.LittleEndian.PutUint32(header[8:], segmentVersion)
	binary.LittleEndian.PutUint64(header[16:], nodeOff)
	binary.LittleEndian.PutUint64(header[24:], nodeCount)
	binary.LittleEndian.PutUint64(header[32:], valueOff)
	binary.LittleEndian.PutUint64(header[40:], valueLen)
	_, err := file.WriteAt(header, 0)
	return err
}

func writeOutputNode(file *os.File, node *outputFrame) error {
	data := make([]byte, segmentNodeSize)
	binary.LittleEndian.PutUint64(data[0:], node.left)
	binary.LittleEndian.PutUint64(data[8:], node.right)
	binary.LittleEndian.PutUint64(data[16:], node.valueOff)
	binary.LittleEndian.PutUint64(data[24:], node.valueLen)
	_, err := file.WriteAt(data, int64(segmentHeaderSize+node.id*segmentNodeSize))
	return err
}

func (t *Trie[T]) compactOldestLocked(count int) error {
	if count < 2 || len(t.segments) < count {
		return nil
	}
	old := append([]*segment[T](nil), t.segments[:count]...)
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
