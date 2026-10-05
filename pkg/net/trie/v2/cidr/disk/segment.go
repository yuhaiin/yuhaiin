package disk

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

const (
	segmentMagic         = "YHCIDR01"
	segmentVersion       = uint32(2)
	legacySegmentVersion = uint32(1)
	segmentHeaderSize    = 64
	segmentNodeSize      = 32
)

// segmentNode is a fixed-width binary prefix node. V1 child IDs are preorder;
// v2 uses postorder IDs and tagged jump links. absentChild marks a missing
// branch. Values in the segment value area use relative offsets and lengths.
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

	version  uint32
	rootID   uint64
	jumpOff  uint64
	jumpCnt  uint64
	nodeOff  uint64
	nodeCnt  uint64
	valueOff uint64
	valueLen uint64
}

func writeSegment[T comparable](path string, root *memoryNode[T], c codec.Codec[T]) (*segment[T], error) {
	return writeCompressedSegment(path, c, func(yield func([]uint8, []T) error) error {
		var storage [129]uint8
		var visit func(*memoryNode[T], []uint8) error
		visit = func(node *memoryNode[T], path []uint8) error {
			if err := yield(path, node.values); err != nil {
				return err
			}
			for branch, child := range node.children {
				if child == nil {
					continue
				}
				if len(path) == len(storage) {
					return errors.New("CIDR path exceeds address width")
				}
				if err := visit(child, append(path, uint8(branch))); err != nil {
					return err
				}
			}
			return nil
		}
		return visit(root, storage[:0])
	})
}

func encodeValues[T comparable](c codec.Codec[T], values []T) ([]byte, error) {
	if len(values) == 0 {
		return nil, nil
	}
	return c.Encode(values)
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
	header, ok := region.BytesAt(0, segmentHeaderSize)
	if !ok || string(header[:8]) != segmentMagic || (binary.LittleEndian.Uint32(header[8:]) != segmentVersion && binary.LittleEndian.Uint32(header[8:]) != legacySegmentVersion) {
		_ = region.Close()
		return nil, fmt.Errorf("invalid disk CIDR segment: %s", path)
	}
	segment := &segment[T]{
		path:     path,
		version:  binary.LittleEndian.Uint32(header[8:]),
		region:   region,
		codec:    c,
		nodeOff:  binary.LittleEndian.Uint64(header[16:]),
		nodeCnt:  binary.LittleEndian.Uint64(header[24:]),
		valueOff: binary.LittleEndian.Uint64(header[32:]),
		valueLen: binary.LittleEndian.Uint64(header[40:]),
	}
	if segment.version == segmentVersion {
		segment.rootID = binary.LittleEndian.Uint64(header[48:])
		segment.jumpOff = binary.LittleEndian.Uint64(header[56:])
	}
	if !segment.valid() {
		_ = region.Close()
		return nil, fmt.Errorf("invalid disk CIDR segment bounds: %s", path)
	}
	root, ok := segment.node(segment.rootID)
	if !ok || !segment.validLink(root.left) || !segment.validLink(root.right) {
		_ = region.Close()
		return nil, fmt.Errorf("invalid disk CIDR segment root: %s", path)
	}
	for family, link := range []uint64{root.left, root.right} {
		if link == absentChild {
			continue
		}
		_, skip, _, ok := segment.decodeLink(link, segment.rootID)
		width := 128
		if family == 0 {
			width = 32
		}
		if !ok || skip > width {
			_ = region.Close()
			return nil, fmt.Errorf("invalid disk CIDR root jump: %s", path)
		}
	}
	return segment, nil
}

func (s *segment[T]) valid() bool {
	if s.nodeCnt == 0 || s.rootID >= s.nodeCnt || s.nodeOff < segmentHeaderSize || s.nodeOff > s.region.Size || s.nodeCnt > (^uint64(0)/segmentNodeSize) {
		return false
	}
	nodeBytes := s.nodeCnt * segmentNodeSize
	if nodeBytes > s.region.Size-s.nodeOff {
		return false
	}
	if s.valueOff < s.nodeOff+nodeBytes || s.valueOff > s.region.Size {
		return false
	}
	if s.version == segmentVersion {
		if s.jumpOff != s.nodeOff+nodeBytes || s.valueOff < s.jumpOff || (s.valueOff-s.jumpOff)%jumpSize != 0 {
			return false
		}
		s.jumpCnt = (s.valueOff - s.jumpOff) / jumpSize
	}
	return s.valueLen <= s.region.Size-s.valueOff
}

func (s *segment[T]) validLink(id uint64) bool {
	if id == absentChild {
		return true
	}
	if s.version == segmentVersion && id&jumpTag != 0 {
		skip := (id >> jumpShift) & 255
		return skip != 0 && skip <= 128 && id&jumpMask < s.jumpCnt
	}
	return id < s.nodeCnt
}

// decodeLink returns the additional skipped bits and the endpoint prefix. V1
// segments have direct links only; v2's postorder IDs also forbid cycles.
func (s *segment[T]) decodeLink(link, parent uint64) (uint64, int, [16]byte, bool) {
	var prefix [16]byte
	if link == absentChild || !s.validLink(link) {
		return 0, 0, prefix, false
	}
	id, skip := link, 0
	if s.version == segmentVersion && link&jumpTag != 0 {
		data, ok := s.region.BytesAt(s.jumpOff+(link&jumpMask)*jumpSize, jumpSize)
		if !ok {
			return 0, 0, prefix, false
		}
		id = binary.LittleEndian.Uint64(data)
		skip = int((link >> jumpShift) & 255)
		copy(prefix[:], data[8:])
	}
	return id, skip, prefix, id < s.nodeCnt && (s.version == legacySegmentVersion || id < parent)
}

// follow validates skipped bits before accepting a compressed endpoint.
func (s *segment[T]) follow(link, parent uint64, expected int, data []byte) (uint64, int, bool) {
	id, skip, prefix, ok := s.decodeLink(link, parent)
	depth := expected + skip
	if !ok || depth > len(data)*8 {
		return 0, 0, false
	}
	if skip != 0 {
		full := depth / 8
		if !bytes.Equal(data[:full], prefix[:full]) {
			return 0, 0, false
		}
		if rem := depth % 8; rem != 0 {
			mask := byte(255 << uint(8-rem))
			if data[full]&mask != prefix[full]&mask {
				return 0, 0, false
			}
		}
	}
	return id, depth, true
}

func (s *segment[T]) node(id uint64) (segmentNode, bool) {
	if id >= s.nodeCnt {
		return segmentNode{}, false
	}
	data, ok := s.region.BytesAt(s.nodeOff+id*segmentNodeSize, segmentNodeSize)
	if !ok {
		return segmentNode{}, false
	}
	node := segmentNode{
		left:     binary.LittleEndian.Uint64(data[0:]),
		right:    binary.LittleEndian.Uint64(data[8:]),
		valueOff: binary.LittleEndian.Uint64(data[16:]),
		valueLen: binary.LittleEndian.Uint64(data[24:]),
	}
	if !s.validLink(node.left) || !s.validLink(node.right) {
		return segmentNode{}, false
	}
	return node, true
}

func (s *segment[T]) valuesNode(id uint64) []T {
	node, ok := s.node(id)
	if !ok {
		return nil
	}
	return s.values(node)
}

func (s *segment[T]) values(node segmentNode) []T {
	if node.valueLen == 0 || node.valueOff > s.valueLen || node.valueLen > s.valueLen-node.valueOff {
		return nil
	}
	data, ok := s.region.BytesAt(s.valueOff+node.valueOff, node.valueLen)
	if !ok {
		return nil
	}
	values, err := s.codec.Decode(data)
	if err != nil {
		return nil
	}
	return cloneValues(values)
}

func (s *segment[T]) appendValues(dst []T, node segmentNode) []T {
	if node.valueLen == 0 || node.valueOff > s.valueLen || node.valueLen > s.valueLen-node.valueOff {
		return dst
	}
	data, ok := s.region.BytesAt(s.valueOff+node.valueOff, node.valueLen)
	if !ok {
		return dst
	}
	result, err := codec.AppendUniqueOwned(s.codec, dst, data)
	if err != nil {
		return dst
	}
	return result
}

// cloneValues detaches string values from the mmap-backed byte slice used by
// UnsafeStringCodec. Other codecs already return owned values and pass through
// this loop unchanged.
func cloneValues[T comparable](values []T) []T {
	for index, value := range values {
		if text, ok := any(value).(string); ok {
			values[index] = any(strings.Clone(text)).(T)
		}
	}
	return values
}

func (s *segment[T]) loadInto(root *memoryNode[T]) error {
	iterator := newSegmentIterator(s)
	for {
		record, ok, err := iterator.next()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		for _, value := range record.values {
			insertPath(root, record.path, value)
		}
	}
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
	return s.region.Close()
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
