package disk

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

const (
	defaultMemoryLimit = 2 << 20

	segmentMagic      = "YHSEG001"
	segmentVersion    = uint32(1)
	segmentHeaderSize = 64
	segmentNodeSize   = 32
	segmentEdgeSize   = 24
)

// segmentNode is the fixed-width on-disk node record. Offsets for values are
// relative to the segment's value area; edge offsets are relative to the edge
// array.
type segmentNode struct {
	firstEdge uint64
	edgeCount uint32
	valueOff  uint64
	valueLen  uint64
}

// segmentEdge is the fixed-width on-disk child record. Labels are stored once
// in the segment label area and referenced by offset and length.
type segmentEdge struct {
	labelOff uint64
	labelLen uint32
	child    uint64
}

type segment[T comparable] struct {
	path   string
	region *region
	codec  codec.Codec[T]

	// rootIndex is intentionally small: it contains only the first label of
	// each path. Besides speeding up root lookups, it lets the Trie reject a
	// segment before walking any deeper nodes.
	rootIndex map[string]uint64

	nodeOff  uint64
	nodeCnt  uint64
	edgeOff  uint64
	edgeCnt  uint64
	labelOff uint64
	valueOff uint64
}

func writeSegment[T comparable](path string, root *memoryNode[T], c codec.Codec[T]) (*segment[T], error) {
	nodes := make([]segmentNode, 0, 1024)
	edges := make([]segmentEdge, 0, 1024)
	labels := make([]byte, 0, 4096)
	values := make([]byte, 0, 4096)
	var encodeErr error

	// Edges are reserved before descending into children. This keeps every
	// node's child range contiguous while still assigning node IDs in preorder.
	var flatten func(*memoryNode[T]) uint64
	flatten = func(node *memoryNode[T]) uint64 {
		id := uint64(len(nodes))
		nodes = append(nodes, segmentNode{})
		encoded, err := encodeValues(c, node.values)
		if err != nil {
			encodeErr = err
			return 0
		}
		valueOff := uint64(len(values))
		values = append(values, encoded...)

		keys := make([]string, 0, len(node.children))
		for key := range node.children {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		firstEdge := uint64(len(edges))
		for _, key := range keys {
			labelOff := uint64(len(labels))
			labels = append(labels, key...)
			edges = append(edges, segmentEdge{labelOff: labelOff, labelLen: uint32(len(key))})
		}
		for i, key := range keys {
			edges[firstEdge+uint64(i)].child = flatten(node.children[key])
		}
		nodes[id] = segmentNode{
			firstEdge: firstEdge,
			edgeCount: uint32(len(keys)),
			valueOff:  valueOff,
			valueLen:  uint64(len(encoded)),
		}
		return id
	}

	flatten(root)
	if encodeErr != nil {
		return nil, encodeErr
	}

	nodeOff := uint64(segmentHeaderSize)
	edgeOff := nodeOff + uint64(len(nodes))*segmentNodeSize
	labelOff := edgeOff + uint64(len(edges))*segmentEdgeSize
	valueOff := labelOff + uint64(len(labels))

	tmp, err := os.CreateTemp(filepath.Dir(path), ".segment-*.tmp")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	header := make([]byte, segmentHeaderSize)
	copy(header, segmentMagic)
	binary.LittleEndian.PutUint32(header[8:], segmentVersion)
	binary.LittleEndian.PutUint64(header[16:], nodeOff)
	binary.LittleEndian.PutUint64(header[24:], uint64(len(nodes)))
	binary.LittleEndian.PutUint64(header[32:], edgeOff)
	binary.LittleEndian.PutUint64(header[40:], uint64(len(edges)))
	binary.LittleEndian.PutUint64(header[48:], labelOff)
	binary.LittleEndian.PutUint64(header[56:], valueOff)
	if err := writeAll(tmp, header); err != nil {
		_ = tmp.Close()
		return nil, err
	}

	nodeBuffer := make([]byte, segmentNodeSize)
	for _, node := range nodes {
		clear(nodeBuffer)
		binary.LittleEndian.PutUint64(nodeBuffer[0:], node.firstEdge)
		binary.LittleEndian.PutUint32(nodeBuffer[8:], node.edgeCount)
		binary.LittleEndian.PutUint64(nodeBuffer[16:], node.valueOff)
		binary.LittleEndian.PutUint64(nodeBuffer[24:], node.valueLen)
		if err := writeAll(tmp, nodeBuffer); err != nil {
			_ = tmp.Close()
			return nil, err
		}
	}

	edgeBuffer := make([]byte, segmentEdgeSize)
	for _, edge := range edges {
		clear(edgeBuffer)
		binary.LittleEndian.PutUint64(edgeBuffer[0:], edge.labelOff)
		binary.LittleEndian.PutUint32(edgeBuffer[8:], edge.labelLen)
		binary.LittleEndian.PutUint64(edgeBuffer[16:], edge.child)
		if err := writeAll(tmp, edgeBuffer); err != nil {
			_ = tmp.Close()
			return nil, err
		}
	}
	if err := writeAll(tmp, labels); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := writeAll(tmp, values); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return nil, err
	}
	return openSegment[T](path, c)
}

func openSegment[T comparable](path string, c codec.Codec[T]) (*segment[T], error) {
	region, err := openRegion(path)
	if err != nil {
		return nil, err
	}
	header, ok := region.bytesAt(0, segmentHeaderSize)
	if !ok || string(header[:8]) != segmentMagic || binary.LittleEndian.Uint32(header[8:]) != segmentVersion {
		_ = region.close()
		return nil, fmt.Errorf("invalid disk trie segment: %s", path)
	}
	segment := &segment[T]{
		path:     path,
		region:   region,
		codec:    c,
		nodeOff:  binary.LittleEndian.Uint64(header[16:]),
		nodeCnt:  binary.LittleEndian.Uint64(header[24:]),
		edgeOff:  binary.LittleEndian.Uint64(header[32:]),
		edgeCnt:  binary.LittleEndian.Uint64(header[40:]),
		labelOff: binary.LittleEndian.Uint64(header[48:]),
		valueOff: binary.LittleEndian.Uint64(header[56:]),
	}
	if !segment.valid() {
		_ = region.close()
		return nil, fmt.Errorf("invalid disk trie segment bounds: %s", path)
	}
	if err := segment.buildRootIndex(); err != nil {
		_ = region.close()
		return nil, err
	}
	return segment, nil
}

func (s *segment[T]) valid() bool {
	dataLen := s.region.size
	sectionEnd := func(offset, count, width uint64) (uint64, bool) {
		if count != 0 && count > ^uint64(0)/width {
			return 0, false
		}
		size := count * width
		if offset > dataLen || size > dataLen-offset {
			return 0, false
		}
		return offset + size, true
	}
	nodeEnd, ok := sectionEnd(s.nodeOff, s.nodeCnt, segmentNodeSize)
	if !ok {
		return false
	}
	edgeEnd, ok := sectionEnd(s.edgeOff, s.edgeCnt, segmentEdgeSize)
	return ok && s.edgeOff >= nodeEnd && s.labelOff >= edgeEnd && s.valueOff >= s.labelOff && s.valueOff <= dataLen
}

func (s *segment[T]) node(id uint64) (segmentNode, bool) {
	if id >= s.nodeCnt {
		return segmentNode{}, false
	}
	data, ok := s.region.bytesAt(s.nodeOff+id*segmentNodeSize, segmentNodeSize)
	if !ok {
		return segmentNode{}, false
	}
	return segmentNode{
		firstEdge: binary.LittleEndian.Uint64(data[0:]),
		edgeCount: binary.LittleEndian.Uint32(data[8:]),
		valueOff:  binary.LittleEndian.Uint64(data[16:]),
		valueLen:  binary.LittleEndian.Uint64(data[24:]),
	}, true
}

func (s *segment[T]) buildRootIndex() error {
	root, ok := s.node(0)
	if !ok || root.firstEdge > s.edgeCnt || uint64(root.edgeCount) > s.edgeCnt-root.firstEdge {
		return errors.New("invalid disk trie root")
	}
	s.rootIndex = make(map[string]uint64, root.edgeCount)
	for i := uint64(0); i < uint64(root.edgeCount); i++ {
		label, child, ok := s.edge(root.firstEdge + i)
		if !ok {
			return errors.New("invalid disk trie root edge")
		}
		s.rootIndex[string(label)] = child
	}
	return nil
}

func (s *segment[T]) mayContainRoot(label string) bool {
	_, ok := s.rootIndex[label]
	return ok
}

func (s *segment[T]) edge(id uint64) ([]byte, uint64, bool) {
	if id >= s.edgeCnt {
		return nil, 0, false
	}
	data, ok := s.region.bytesAt(s.edgeOff+id*segmentEdgeSize, segmentEdgeSize)
	if !ok {
		return nil, 0, false
	}
	labelOff := s.labelOff + binary.LittleEndian.Uint64(data[0:])
	labelLen := uint64(binary.LittleEndian.Uint32(data[8:]))
	if labelOff < s.labelOff || labelOff > s.valueOff || labelLen > s.valueOff-labelOff {
		return nil, 0, false
	}
	label, ok := s.region.bytesAt(labelOff, labelLen)
	if !ok {
		return nil, 0, false
	}
	child := binary.LittleEndian.Uint64(data[16:])
	if child >= s.nodeCnt {
		return nil, 0, false
	}
	return label, child, true
}

// child finds a child node. Root children use the small path index; deeper
// nodes use binary search over their sorted edge range.
func (s *segment[T]) child(id uint64, label string) (uint64, bool) {
	if id == 0 {
		child, ok := s.rootIndex[label]
		return child, ok
	}
	node, ok := s.node(id)
	if !ok || node.firstEdge > s.edgeCnt || uint64(node.edgeCount) > s.edgeCnt-node.firstEdge {
		return 0, false
	}
	target := []byte(label)
	lo, hi := uint64(0), uint64(node.edgeCount)
	for lo < hi {
		mid := lo + (hi-lo)/2
		labelBytes, child, ok := s.edge(node.firstEdge + mid)
		if !ok {
			return 0, false
		}
		compare := bytes.Compare(labelBytes, target)
		if compare == 0 {
			return child, true
		}
		if compare < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return 0, false
}

func (s *segment[T]) childPath(path []string, label string) bool {
	id := uint64(0)
	rest := path
	if len(path) != 0 {
		var ok bool
		id, ok = s.rootIndex[path[0]]
		if !ok {
			return false
		}
		rest = path[1:]
	}
	for _, part := range rest {
		var ok bool
		id, ok = s.child(id, part)
		if !ok {
			return false
		}
	}
	_, ok := s.child(id, label)
	return ok
}

func (s *segment[T]) valuesPath(path []string) []T {
	id := uint64(0)
	rest := path
	if len(path) != 0 {
		var ok bool
		id, ok = s.rootIndex[path[0]]
		if !ok {
			return nil
		}
		rest = path[1:]
	}
	for _, part := range rest {
		var ok bool
		id, ok = s.child(id, part)
		if !ok {
			return nil
		}
	}
	return s.valuesNode(id)
}

func (s *segment[T]) valuesNode(id uint64) []T {
	node, ok := s.node(id)
	if !ok || node.valueOff > s.region.size-s.valueOff || node.valueLen > s.region.size-s.valueOff-node.valueOff {
		return nil
	}
	data, ok := s.region.bytesAt(s.valueOff+node.valueOff, node.valueLen)
	if !ok {
		return nil
	}
	values, err := s.codec.Decode(data)
	if err != nil {
		return nil
	}
	return cloneValues(values)
}

func cloneValues[T comparable](values []T) []T {
	for i, value := range values {
		if text, ok := any(value).(string); ok {
			values[i] = any(string([]byte(text))).(T)
		}
	}
	return values
}

func (s *segment[T]) loadInto(root *memoryNode[T], path []string) error {
	id := uint64(0)
	for _, part := range path {
		var ok bool
		id, ok = s.child(id, part)
		if !ok {
			return errors.New("invalid disk trie path")
		}
	}
	return s.loadNode(root, path, id)
}

func (s *segment[T]) loadNode(root *memoryNode[T], path []string, id uint64) error {
	node, ok := s.node(id)
	if !ok || node.firstEdge > s.edgeCnt || uint64(node.edgeCount) > s.edgeCnt-node.firstEdge {
		return errors.New("invalid disk trie node")
	}
	for _, value := range s.valuesPath(path) {
		insertMemoryNode(root, path, value)
	}
	for i := uint64(0); i < uint64(node.edgeCount); i++ {
		label, child, ok := s.edge(node.firstEdge + i)
		if !ok {
			return errors.New("invalid disk trie edge")
		}
		if err := s.loadNode(root, append(path, string(label)), child); err != nil {
			return err
		}
	}
	return nil
}

func (s *segment[T]) close() error {
	return s.region.close()
}

func globSegments(dir string) []string {
	files, _ := filepath.Glob(filepath.Join(dir, "segment-*.mmap"))
	return files
}

func segmentID(path string) (uint64, bool) {
	name := strings.TrimSuffix(filepath.Base(path), ".mmap")
	id, err := strconv.ParseUint(strings.TrimPrefix(name, "segment-"), 10, 64)
	return id, err == nil
}
