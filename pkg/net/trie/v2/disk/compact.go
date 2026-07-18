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

const (
	segmentCompactionThreshold = 4
	planNodeSize               = 32
)

type segmentRecord[T comparable] struct {
	path   []string
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
	path    []string
}

func newSegmentIterator[T comparable](segment *segment[T]) *segmentIterator[T] {
	return &segmentIterator[T]{segment: segment, stack: []segmentFrame{{id: 0}}}
}

func (it *segmentIterator[T]) next() (segmentRecord[T], bool, error) {
	for len(it.stack) != 0 {
		top := &it.stack[len(it.stack)-1]
		node, ok := it.segment.node(top.id)
		if !ok || top.next > uint64(node.edgeCount) {
			return segmentRecord[T]{}, false, errors.New("invalid disk trie iterator node")
		}
		if !top.entered {
			top.entered = true
			path := append([]string(nil), it.path...)
			return segmentRecord[T]{path: path, values: it.segment.valuesNode(top.id)}, true, nil
		}
		if top.next < uint64(node.edgeCount) {
			label, child, ok := it.segment.edge(node.firstEdge + top.next)
			if !ok {
				return segmentRecord[T]{}, false, errors.New("invalid disk trie iterator edge")
			}
			top.next++
			it.path = append(it.path, string(label))
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
	if cmp := comparePath(h[i].record.path, h[j].record.path); cmp != 0 {
		return cmp < 0
	}
	return h[i].order < h[j].order
}

func (h mergeHeap[T]) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *mergeHeap[T]) Push(value any) { *h = append(*h, value.(*mergeItem[T])) }

func (h *mergeHeap[T]) Pop() any {
	old := *h
	n := len(old)
	value := old[n-1]
	*h = old[:n-1]
	return value
}

func comparePath(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
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

func forEachMerged[T comparable](parts []*segment[T], fn func([]string, []T) error) error {
	// Each segment is traversed once. The heap keeps only the next record from
	// each input, so compaction memory grows with the number of segments, not
	// with the total number of indexed domains.
	h := make(mergeHeap[T], 0, len(parts))
	for i, part := range parts {
		iterator := newSegmentIterator(part)
		record, ok, err := iterator.next()
		if err != nil {
			return err
		}
		if ok {
			heap.Push(&h, &mergeItem[T]{iterator: iterator, record: record, order: i})
		}
	}

	for h.Len() != 0 {
		first := heap.Pop(&h).(*mergeItem[T])
		path := first.record.path
		values := append([]T(nil), first.record.values...)
		items := []*mergeItem[T]{first}
		for h.Len() != 0 && comparePath(h[0].record.path, path) == 0 {
			item := heap.Pop(&h).(*mergeItem[T])
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
				heap.Push(&h, item)
			}
		}
	}
	return nil
}

type planNode struct {
	edgeCount uint32
	valueOff  uint64
	valueLen  uint64
}

type planState struct {
	offset    int64
	edgeCount uint32
}

type compactionStats struct {
	nodes  uint64
	edges  uint64
	labels uint64
	values uint64
}

func encodeValues[T comparable](c codec.Codec[T], values []T) ([]byte, error) {
	if len(values) == 0 {
		return nil, nil
	}
	return c.Encode(values)
}

func writePlanNode(file *os.File, offset int64, node planNode) error {
	data := make([]byte, planNodeSize)
	binary.LittleEndian.PutUint32(data[0:], node.edgeCount)
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
		return planNode{}, errors.New("short disk trie compaction plan")
	}
	return planNode{
		edgeCount: binary.LittleEndian.Uint32(data[0:]),
		valueOff:  binary.LittleEndian.Uint64(data[8:]),
		valueLen:  binary.LittleEndian.Uint64(data[16:]),
	}, nil
}

func buildCompactionPlan[T comparable](dir string, parts []*segment[T], c codec.Codec[T]) (string, compactionStats, error) {
	// The plan records the output tree's shape and encoded value offsets. A
	// separate plan pass lets the final segment be allocated exactly without
	// building the compacted tree in memory.
	file, err := os.CreateTemp(dir, ".compaction-plan-*")
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
	var previous []string
	err = forEachMerged(parts, func(path []string, values []T) error {
		common := commonPath(previous, path)
		for len(stack)-1 > common {
			stack = stack[:len(stack)-1]
		}
		if len(path) > common+1 {
			return errors.New("disk trie compaction stream skipped a path node")
		}
		if len(path) == common+1 {
			parent := &stack[len(stack)-1]
			parent.edgeCount++
			if err := writePlanNode(file, parent.offset, planNode{edgeCount: parent.edgeCount}); err != nil {
				return err
			}
			stats.edges++
			stats.labels += uint64(len(path[common]))
			state := planState{offset: int64(stats.nodes) * planNodeSize}
			stack = append(stack, state)
			stats.nodes++
			if err := writePlanNode(file, state.offset, planNode{}); err != nil {
				return err
			}
		}

		encoded, err := encodeValues(c, values)
		if err != nil {
			return err
		}
		current := &stack[len(stack)-1]
		if err := writePlanNode(file, current.offset, planNode{
			edgeCount: current.edgeCount,
			valueOff:  stats.values,
			valueLen:  uint64(len(encoded)),
		}); err != nil {
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

func commonPath(a, b []string) int {
	n := min(len(b), len(a))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

func compactSegments[T comparable](path string, parts []*segment[T], c codec.Codec[T]) (*segment[T], error) {
	// The merged stream is replayed twice: once to calculate layout and once to
	// write the final random-access segment. Both passes remain bounded-memory.
	planPath, stats, err := buildCompactionPlan(filepath.Dir(path), parts, c)
	if err != nil {
		return nil, err
	}
	defer os.Remove(planPath)

	tmp, err := os.CreateTemp(filepath.Dir(path), ".compacted-segment-*")
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
	edgeOff := nodeOff + stats.nodes*segmentNodeSize
	labelOff := edgeOff + stats.edges*segmentEdgeSize
	valueOff := labelOff + stats.labels
	total := valueOff + stats.values
	if err := tmp.Truncate(int64(total)); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	header := make([]byte, segmentHeaderSize)
	copy(header, segmentMagic)
	binary.LittleEndian.PutUint32(header[8:], segmentVersion)
	binary.LittleEndian.PutUint64(header[16:], nodeOff)
	binary.LittleEndian.PutUint64(header[24:], stats.nodes)
	binary.LittleEndian.PutUint64(header[32:], edgeOff)
	binary.LittleEndian.PutUint64(header[40:], stats.edges)
	binary.LittleEndian.PutUint64(header[48:], labelOff)
	binary.LittleEndian.PutUint64(header[56:], valueOff)
	if _, err := tmp.WriteAt(header, 0); err != nil {
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

	type outputFrame struct {
		id        uint64
		firstEdge uint64
		edgeCount uint32
		nextEdge  uint32
	}
	stack := make([]outputFrame, 0, 8)
	var previous []string
	var nodeID, edgeCursor, labelCursor uint64
	err = forEachMerged(parts, func(path []string, values []T) error {
		common := commonPath(previous, path)
		for len(stack)-1 > common {
			stack = stack[:len(stack)-1]
		}
		if len(path) > common+1 {
			return errors.New("disk trie compaction output skipped a path node")
		}
		if len(path) == common+1 {
			parent := &stack[len(stack)-1]
			if parent.nextEdge >= parent.edgeCount {
				return errors.New("disk trie compaction parent edge overflow")
			}
			childID := nodeID
			edgeID := parent.firstEdge + uint64(parent.nextEdge)
			parent.nextEdge++
			labelBytes := []byte(path[common])
			labelAt := labelOff + labelCursor
			if _, err := tmp.WriteAt(labelBytes, int64(labelAt)); err != nil {
				return err
			}
			labelCursor += uint64(len(labelBytes))
			edge := make([]byte, segmentEdgeSize)
			binary.LittleEndian.PutUint64(edge[0:], labelCursor-uint64(len(labelBytes)))
			binary.LittleEndian.PutUint32(edge[8:], uint32(len(labelBytes)))
			binary.LittleEndian.PutUint64(edge[16:], childID)
			if _, err := tmp.WriteAt(edge, int64(edgeOff+edgeID*segmentEdgeSize)); err != nil {
				return err
			}
		}

		planNode, err := readPlanNode(plan, int64(nodeID)*planNodeSize)
		if err != nil {
			return err
		}
		if nodeID != 0 && len(path) != common+1 {
			return errors.New("disk trie compaction duplicate path")
		}
		firstEdge := edgeCursor
		edgeCursor += uint64(planNode.edgeCount)
		node := make([]byte, segmentNodeSize)
		binary.LittleEndian.PutUint64(node[0:], firstEdge)
		binary.LittleEndian.PutUint32(node[8:], planNode.edgeCount)
		binary.LittleEndian.PutUint64(node[16:], planNode.valueOff)
		binary.LittleEndian.PutUint64(node[24:], planNode.valueLen)
		if _, err := tmp.WriteAt(node, int64(nodeOff+nodeID*segmentNodeSize)); err != nil {
			return err
		}
		if planNode.valueLen != 0 {
			encoded, err := encodeValues(c, values)
			if err != nil {
				return err
			}
			if uint64(len(encoded)) != planNode.valueLen {
				return errors.New("disk trie compaction value size changed")
			}
			if _, err := tmp.WriteAt(encoded, int64(valueOff+planNode.valueOff)); err != nil {
				return err
			}
		}
		stack = append(stack, outputFrame{id: nodeID, firstEdge: firstEdge, edgeCount: planNode.edgeCount})
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

func (t *Trie[T]) compactOldestLocked(count int) error {
	if count < 2 || len(t.segments) < count {
		return nil
	}
	old := append([]*segment[T](nil), t.segments[:count]...)
	finalPath := old[0].path
	tmpPath := filepath.Join(t.dir, fmt.Sprintf(".compact-%020d.mmap", t.nextSegmentID))
	merged, err := compactSegments(tmpPath, old, t.codec)
	if err != nil {
		return err
	}
	if err := merged.close(); err != nil {
		return err
	}
	for _, part := range old {
		if err := part.close(); err != nil {
			return err
		}
		if err := os.Remove(part.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return err
	}
	newPart, err := openSegment[T](finalPath, t.codec)
	if err != nil {
		return err
	}
	t.segments = append([]*segment[T]{newPart}, t.segments[count:]...)
	return nil
}
