package disk

import (
	"bufio"
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
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/internal/diskio"
)

const (
	defaultMemoryLimit = 2 << 20

	segmentMagic      = "YHSEG001"
	segmentVersion    = uint32(1)
	segmentHeaderSize = 64
	segmentNodeSize   = 32
	segmentEdgeSize   = 24
	wildcardKnown     = uint32(1) << 31
	wildcardIndexMask = wildcardKnown - 1
)

// segmentNode is the fixed-width on-disk node record. Offsets for values are
// relative to the segment's value area; edge offsets are relative to the edge
// array. The formerly reserved wildcard field uses its high bit to mark
// known metadata and a one-based edge index in the low bits (zero means none).
// Legacy nodes leave this field zero; older readers ignore it.
type segmentNode struct {
	firstEdge uint64
	edgeCount uint32
	wildcard  uint32
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

	ownedValues                              bool
	nodeData, edgeData, labelData, valueData []byte

	// rootIndex is intentionally small: it contains only the first label of
	// each path. Besides speeding up root lookups, it lets the Trie reject a
	// segment before walking any deeper nodes.
	rootIndex map[string]uint64
	rootNode  segmentNode

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
		valueOff := uint64(len(values))
		if len(node.values) != 0 {
			var err error
			values, err = codec.AppendEncode(c, values, node.values)
			if err != nil {
				encodeErr = err
				return 0
			}
		}
		valueLen := uint64(len(values)) - valueOff

		keys := make([]string, 0, len(node.children))
		for key := range node.children {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		firstEdge := uint64(len(edges))
		wildcard := wildcardKnown
		for index, key := range keys {
			if key == "*" {
				if uint64(index) < uint64(wildcardIndexMask) {
					wildcard |= uint32(index) + 1
				} else {
					wildcard = 0
				}
			}
			labelOff := uint64(len(labels))
			labels = append(labels, key...)
			edges = append(edges, segmentEdge{labelOff: labelOff, labelLen: uint32(len(key))})
		}
		for i, key := range keys {
			edges[firstEdge+uint64(i)].child = flatten(node.children[key])
		}
		nodes[id] = segmentNode{
			wildcard:  wildcard,
			firstEdge: firstEdge,
			edgeCount: uint32(len(keys)),
			valueOff:  valueOff,
			valueLen:  valueLen,
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
	writer := bufio.NewWriterSize(tmp, diskio.BufferSize)
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
	if err := writeAll(writer, header); err != nil {
		_ = tmp.Close()
		return nil, err
	}

	nodeBuffer := make([]byte, segmentNodeSize)
	for _, node := range nodes {
		clear(nodeBuffer)
		binary.LittleEndian.PutUint64(nodeBuffer[0:], node.firstEdge)
		binary.LittleEndian.PutUint32(nodeBuffer[8:], node.edgeCount)
		binary.LittleEndian.PutUint32(nodeBuffer[12:], node.wildcard)
		binary.LittleEndian.PutUint64(nodeBuffer[16:], node.valueOff)
		binary.LittleEndian.PutUint64(nodeBuffer[24:], node.valueLen)
		if err := writeAll(writer, nodeBuffer); err != nil {
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
		if err := writeAll(writer, edgeBuffer); err != nil {
			_ = tmp.Close()
			return nil, err
		}
	}
	if err := writeAll(writer, labels); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := writeAll(writer, values); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := writer.Flush(); err != nil {
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
	header, ok := region.BytesAt(0, segmentHeaderSize)
	if !ok || string(header[:8]) != segmentMagic || binary.LittleEndian.Uint32(header[8:]) != segmentVersion {
		_ = region.Close()
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
		_ = region.Close()
		return nil, fmt.Errorf("invalid disk trie segment bounds: %s", path)
	}
	segment.nodeData, _ = region.MappedBytes(segment.nodeOff, segment.nodeCnt*segmentNodeSize)
	segment.edgeData, _ = region.MappedBytes(segment.edgeOff, segment.edgeCnt*segmentEdgeSize)
	segment.labelData, _ = region.MappedBytes(segment.labelOff, segment.valueOff-segment.labelOff)
	segment.valueData, _ = region.MappedBytes(segment.valueOff, region.Size-segment.valueOff)
	switch any(c).(type) {
	case codec.UnsafeStringCodec, *codec.UnsafeStringCodec:
		reader, ok := region.Reader(segment.valueOff, region.Size-segment.valueOff)
		if !ok {
			region.Close()
			return nil, errors.New("invalid string pool area")
		}
		pool, err := codec.NewPooledStringCodec(reader)
		if err != nil {
			region.Close()
			return nil, err
		}
		if pool != nil {
			segment.codec = any(pool).(codec.Codec[T])
			segment.ownedValues = true
		}
	}
	if err := segment.buildRootIndex(); err != nil {
		_ = region.Close()
		return nil, err
	}
	return segment, nil
}

func (s *segment[T]) valid() bool {
	dataLen := s.region.Size
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
	var data []byte
	if s.nodeData != nil {
		offset := id * segmentNodeSize
		data = s.nodeData[offset : offset+segmentNodeSize]
	} else {
		var ok bool
		data, ok = s.region.BytesAt(s.nodeOff+id*segmentNodeSize, segmentNodeSize)
		if !ok {
			return segmentNode{}, false
		}
	}
	return segmentNode{
		firstEdge: binary.LittleEndian.Uint64(data[0:]),
		edgeCount: binary.LittleEndian.Uint32(data[8:]),
		wildcard:  binary.LittleEndian.Uint32(data[12:]),
		valueOff:  binary.LittleEndian.Uint64(data[16:]),
		valueLen:  binary.LittleEndian.Uint64(data[24:]),
	}, true
}

func (s *segment[T]) buildRootIndex() error {
	root, ok := s.node(0)
	if !ok || root.firstEdge > s.edgeCnt || uint64(root.edgeCount) > s.edgeCnt-root.firstEdge {
		return errors.New("invalid disk trie root")
	}
	s.rootNode = root
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

func (s *segment[T]) edge(id uint64) ([]byte, uint64, bool) {
	if id >= s.edgeCnt {
		return nil, 0, false
	}
	var data, label []byte
	if s.edgeData != nil {
		offset := id * segmentEdgeSize
		data = s.edgeData[offset : offset+segmentEdgeSize]
		labelOff := binary.LittleEndian.Uint64(data)
		labelLen := uint64(binary.LittleEndian.Uint32(data[8:]))
		if labelOff > uint64(len(s.labelData)) || labelLen > uint64(len(s.labelData))-labelOff {
			return nil, 0, false
		}
		label = s.labelData[labelOff : labelOff+labelLen]
	} else {
		var ok bool
		data, ok = s.region.BytesAt(s.edgeOff+id*segmentEdgeSize, segmentEdgeSize)
		if !ok {
			return nil, 0, false
		}
		labelOff := s.labelOff + binary.LittleEndian.Uint64(data)
		labelLen := uint64(binary.LittleEndian.Uint32(data[8:]))
		if labelOff < s.labelOff || labelOff > s.valueOff || labelLen > s.valueOff-labelOff {
			return nil, 0, false
		}
		label, ok = s.region.BytesAt(labelOff, labelLen)
		if !ok {
			return nil, 0, false
		}
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
	node, ok := s.node(id)
	if !ok {
		return 0, false
	}
	return s.childNode(id, node, label)
}

// childNode uses an already parsed node, avoiding repeated region reads during
// exact/wildcard lookup. Zero wildcard metadata denotes a legacy node.
func (s *segment[T]) childNode(id uint64, node segmentNode, label string) (uint64, bool) {
	if id == 0 {
		child, ok := s.rootIndex[label]
		return child, ok
	}
	if node.firstEdge > s.edgeCnt || uint64(node.edgeCount) > s.edgeCnt-node.firstEdge {
		return 0, false
	}
	if label == "*" && node.wildcard&wildcardKnown != 0 {
		index := node.wildcard & wildcardIndexMask
		if index == 0 || index > node.edgeCount {
			return 0, false
		}
		labelBytes, child, ok := s.edge(node.firstEdge + uint64(index) - 1)
		return child, ok && len(labelBytes) == 1 && labelBytes[0] == '*'
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

func (s *segment[T]) valueBytes(node segmentNode) ([]byte, bool) {
	if node.valueOff > s.region.Size-s.valueOff || node.valueLen > s.region.Size-s.valueOff-node.valueOff {
		return nil, false
	}
	if s.valueData != nil {
		return s.valueData[node.valueOff : node.valueOff+node.valueLen], true
	}
	return s.region.BytesAt(s.valueOff+node.valueOff, node.valueLen)
}

func (s *segment[T]) valuesNode(id uint64) []T {
	node, ok := s.node(id)
	if !ok || node.valueLen == 0 || node.valueOff > s.region.Size-s.valueOff || node.valueLen > s.region.Size-s.valueOff-node.valueOff {
		return nil
	}
	data, ok := s.valueBytes(node)
	if !ok {
		return nil
	}
	values, err := s.codec.Decode(data)
	if err != nil {
		return nil
	}
	if s.ownedValues {
		return values
	}
	return cloneValues(values)
}

func (s *segment[T]) appendValues(dst []T, node segmentNode) []T {
	if node.valueLen == 0 || node.valueOff > s.region.Size-s.valueOff || node.valueLen > s.region.Size-s.valueOff-node.valueOff {
		return dst
	}
	data, ok := s.valueBytes(node)
	if !ok {
		return dst
	}
	result, err := codec.AppendUniqueOwned(s.codec, dst, data)
	if err != nil {
		return dst
	}
	return result
}

func cloneValues[T comparable](values []T) []T {
	for i, value := range values {
		if text, ok := any(value).(string); ok {
			values[i] = any(strings.Clone(text)).(T)
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
	for _, value := range s.valuesNode(id) {
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
	err := s.region.Close()
	s.nodeData, s.edgeData, s.labelData, s.valueData = nil, nil, nil, nil
	return err
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
