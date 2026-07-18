package disk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

const (
	segmentMagic      = "YHCIDR01"
	segmentVersion    = uint32(1)
	segmentHeaderSize = 64
	segmentNodeSize   = 32
)

// segmentNode is a fixed-width binary prefix node. Child IDs are preorder
// node offsets; absentChild marks a missing branch. Values are stored in the
// segment value area and referenced by relative offset and length.
type segmentNode struct {
	left     uint64
	right    uint64
	valueOff uint64
	valueLen uint64
}

type segment[T comparable] struct {
	path   string
	region *region
	codec  codec.Codec[T]

	nodeOff  uint64
	nodeCnt  uint64
	valueOff uint64
	valueLen uint64
}

func writeSegment[T comparable](path string, root *memoryNode[T], c codec.Codec[T]) (*segment[T], error) {
	nodes := make([]segmentNode, 0, 1024)
	values := make([]byte, 0, 4096)
	var encodeErr error

	var flatten func(*memoryNode[T]) uint64
	flatten = func(node *memoryNode[T]) uint64 {
		id := uint64(len(nodes))
		nodes = append(nodes, segmentNode{left: absentChild, right: absentChild})
		encoded, err := encodeValues(c, node.values)
		if err != nil {
			encodeErr = err
			return 0
		}
		valueOff := uint64(len(values))
		values = append(values, encoded...)

		left := absentChild
		if node.children[0] != nil {
			left = flatten(node.children[0])
		}
		right := absentChild
		if node.children[1] != nil {
			right = flatten(node.children[1])
		}
		nodes[id] = segmentNode{
			left:     left,
			right:    right,
			valueOff: valueOff,
			valueLen: uint64(len(encoded)),
		}
		return id
	}

	flatten(root)
	if encodeErr != nil {
		return nil, encodeErr
	}

	nodeOff := uint64(segmentHeaderSize)
	valueOff := nodeOff + uint64(len(nodes))*segmentNodeSize
	tmp, err := os.CreateTemp(filepath.Dir(path), ".segment-*.tmp")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := writeSegmentHeader(tmp, nodeOff, uint64(len(nodes)), valueOff, uint64(len(values))); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	nodeBuffer := make([]byte, segmentNodeSize)
	for _, node := range nodes {
		encodeNode(nodeBuffer, node)
		if err := writeAll(tmp, nodeBuffer); err != nil {
			_ = tmp.Close()
			return nil, err
		}
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

func encodeValues[T comparable](c codec.Codec[T], values []T) ([]byte, error) {
	if len(values) == 0 {
		return nil, nil
	}
	return c.Encode(values)
}

func writeSegmentHeader(file *os.File, nodeOff, nodeCount, valueOff, valueLen uint64) error {
	header := make([]byte, segmentHeaderSize)
	copy(header, segmentMagic)
	binary.LittleEndian.PutUint32(header[8:], segmentVersion)
	binary.LittleEndian.PutUint64(header[16:], nodeOff)
	binary.LittleEndian.PutUint64(header[24:], nodeCount)
	binary.LittleEndian.PutUint64(header[32:], valueOff)
	binary.LittleEndian.PutUint64(header[40:], valueLen)
	return writeAll(file, header)
}

func encodeNode(buffer []byte, node segmentNode) {
	clear(buffer)
	binary.LittleEndian.PutUint64(buffer[0:], node.left)
	binary.LittleEndian.PutUint64(buffer[8:], node.right)
	binary.LittleEndian.PutUint64(buffer[16:], node.valueOff)
	binary.LittleEndian.PutUint64(buffer[24:], node.valueLen)
}

func openSegment[T comparable](path string, c codec.Codec[T]) (*segment[T], error) {
	region, err := openRegion(path)
	if err != nil {
		return nil, err
	}
	header, ok := region.bytesAt(0, segmentHeaderSize)
	if !ok || string(header[:8]) != segmentMagic || binary.LittleEndian.Uint32(header[8:]) != segmentVersion {
		_ = region.close()
		return nil, fmt.Errorf("invalid disk CIDR segment: %s", path)
	}
	segment := &segment[T]{
		path:     path,
		region:   region,
		codec:    c,
		nodeOff:  binary.LittleEndian.Uint64(header[16:]),
		nodeCnt:  binary.LittleEndian.Uint64(header[24:]),
		valueOff: binary.LittleEndian.Uint64(header[32:]),
		valueLen: binary.LittleEndian.Uint64(header[40:]),
	}
	if !segment.valid() {
		_ = region.close()
		return nil, fmt.Errorf("invalid disk CIDR segment bounds: %s", path)
	}
	root, ok := segment.node(0)
	if !ok || !validChild(root.left, segment.nodeCnt) || !validChild(root.right, segment.nodeCnt) {
		_ = region.close()
		return nil, fmt.Errorf("invalid disk CIDR segment root: %s", path)
	}
	return segment, nil
}

func (s *segment[T]) valid() bool {
	if s.nodeCnt == 0 || s.nodeOff > s.region.size || s.nodeCnt > (^uint64(0)/segmentNodeSize) {
		return false
	}
	nodeBytes := s.nodeCnt * segmentNodeSize
	if nodeBytes > s.region.size-s.nodeOff {
		return false
	}
	if s.valueOff < s.nodeOff+nodeBytes || s.valueOff > s.region.size {
		return false
	}
	return s.valueLen <= s.region.size-s.valueOff
}

func validChild(id, nodeCount uint64) bool {
	return id == absentChild || id < nodeCount
}

func (s *segment[T]) node(id uint64) (segmentNode, bool) {
	if id >= s.nodeCnt {
		return segmentNode{}, false
	}
	data, ok := s.region.bytesAt(s.nodeOff+id*segmentNodeSize, segmentNodeSize)
	if !ok {
		return segmentNode{}, false
	}
	node := segmentNode{
		left:     binary.LittleEndian.Uint64(data[0:]),
		right:    binary.LittleEndian.Uint64(data[8:]),
		valueOff: binary.LittleEndian.Uint64(data[16:]),
		valueLen: binary.LittleEndian.Uint64(data[24:]),
	}
	if !validChild(node.left, s.nodeCnt) || !validChild(node.right, s.nodeCnt) {
		return segmentNode{}, false
	}
	return node, true
}

func (s *segment[T]) valuesNode(id uint64) []T {
	node, ok := s.node(id)
	if !ok || node.valueOff > s.valueLen || node.valueLen > s.valueLen-node.valueOff {
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

// cloneValues detaches string values from the mmap-backed byte slice used by
// UnsafeStringCodec. Other codecs already return owned values and pass through
// this loop unchanged.
func cloneValues[T comparable](values []T) []T {
	for index, value := range values {
		if text, ok := any(value).(string); ok {
			values[index] = any(string([]byte(text))).(T)
		}
	}
	return values
}

func (s *segment[T]) search(data []byte) []T {
	var result []T
	root, ok := s.node(0)
	if !ok {
		return nil
	}
	nodeID := root.right
	if len(data) == netIPv4Bytes {
		nodeID = root.left
	}
	if nodeID == absentChild {
		return nil
	}
	if values := s.valuesNode(nodeID); len(values) != 0 {
		result = appendUnique(result, values...)
	}
	for index := 0; index < len(data)*8; index++ {
		node, ok := s.node(nodeID)
		if !ok {
			return result
		}
		nodeID = node.right
		if bitAt(data, index) == 0 {
			nodeID = node.left
		}
		if nodeID == absentChild {
			return result
		}
		if values := s.valuesNode(nodeID); len(values) != 0 {
			result = appendUnique(result, values...)
		}
	}
	return result
}

func (s *segment[T]) loadInto(root *memoryNode[T]) error {
	return s.loadNode(root, 0, nil)
}

func (s *segment[T]) loadNode(root *memoryNode[T], id uint64, path []uint8) error {
	node, ok := s.node(id)
	if !ok {
		return errors.New("invalid disk CIDR node")
	}
	for _, value := range s.valuesNode(id) {
		insertPath(root, path, value)
	}
	if node.left != absentChild {
		if err := s.loadNode(root, node.left, append(path, 0)); err != nil {
			return err
		}
	}
	if node.right != absentChild {
		if err := s.loadNode(root, node.right, append(path, 1)); err != nil {
			return err
		}
	}
	return nil
}

func insertPath[T comparable](root *memoryNode[T], path []uint8, value T) {
	node := root
	for _, branch := range path {
		if node.children[branch] == nil {
			node.children[branch] = newMemoryNode[T]()
		}
		node = node.children[branch]
	}
	if slices.Contains(node.values, value) {
		return
	}
	node.values = append(node.values, value)
}

func (s *segment[T]) close() error {
	return s.region.close()
}

func globSegments(dir string) []string {
	files, _ := filepath.Glob(filepath.Join(dir, "segment-*.cidr"))
	return files
}

func segmentID(path string) (uint64, bool) {
	name := strings.TrimSuffix(filepath.Base(path), ".cidr")
	id, err := strconv.ParseUint(strings.TrimPrefix(name, "segment-"), 10, 64)
	return id, err == nil
}
