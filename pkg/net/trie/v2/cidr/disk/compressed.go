package disk

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/internal/diskio"
)

const (
	jumpTag   = uint64(1) << 63
	jumpShift = 55
	jumpMask  = uint64(1)<<jumpShift - 1
	jumpSize  = 24
)

type childRef struct {
	id      uint64
	depth   int
	prefix  [16]byte
	present bool
}

type compressedFrame struct {
	children           [2]childRef
	prefix             [16]byte
	depth              int
	branch             uint8
	valueOff, valueLen uint64
}

type compressedStats struct{ nodes, jumps, values uint64 }
type compressedOutput struct {
	nodes, jumps, values *diskio.WriterAt
}

type recordWalk[T comparable] func(func([]uint8, []T) error) error

// compressedPass retains only the active path. Empty unary nodes forward their
// child's reference; kept nodes are emitted in postorder, requiring no patches
// or full-size node/value arrays. The root is always retained.
func compressedPass[T comparable](walk recordWalk[T], c codec.Codec[T], output *compressedOutput) (compressedStats, error) {
	var stats compressedStats
	stack := make([]compressedFrame, 1, 130)
	stack[0].depth = -1 // The root's two branches select IPv4/IPv6, not address bits.
	var previous []uint8

	finish := func(frame compressedFrame) (childRef, error) {
		left, right := frame.children[0], frame.children[1]
		if frame.depth >= 0 && frame.valueLen == 0 && left.present != right.present {
			if left.present {
				return left, nil
			}
			return right, nil
		}
		node := segmentNode{left: absentChild, right: absentChild, valueOff: frame.valueOff, valueLen: frame.valueLen}
		for branch, child := range frame.children {
			if !child.present {
				continue
			}
			link := child.id
			expected := frame.depth + 1
			skip := child.depth - expected
			if skip < 0 || skip > 128 {
				return childRef{}, errors.New("invalid compressed CIDR depth")
			}
			if skip != 0 {
				if stats.jumps >= jumpMask {
					return childRef{}, errors.New("too many CIDR jumps")
				}
				link = jumpTag | uint64(skip)<<jumpShift | stats.jumps
				if output != nil {
					var data [jumpSize]byte
					binary.LittleEndian.PutUint64(data[:8], child.id)
					copy(data[8:], child.prefix[:])
					if _, err := output.jumps.WriteAt(data[:], int64(stats.jumps*jumpSize)); err != nil {
						return childRef{}, err
					}
				}
				stats.jumps++
			}
			if branch == 0 {
				node.left = link
			} else {
				node.right = link
			}
		}
		id := stats.nodes
		if id >= jumpTag {
			return childRef{}, errors.New("too many CIDR nodes")
		}
		if output != nil {
			var data [segmentNodeSize]byte
			encodeNode(data[:], node)
			if _, err := output.nodes.WriteAt(data[:], int64(id*segmentNodeSize)); err != nil {
				return childRef{}, err
			}
		}
		stats.nodes++
		return childRef{id: id, depth: frame.depth, prefix: frame.prefix, present: true}, nil
	}
	err := walk(func(path []uint8, values []T) error {
		if len(path) > 129 {
			return errors.New("CIDR path exceeds address width")
		}
		common := commonPath(previous, path)
		for len(stack)-1 > common {
			frame := stack[len(stack)-1]
			ref, err := finish(frame)
			if err != nil {
				return err
			}
			stack = stack[:len(stack)-1]
			stack[len(stack)-1].children[frame.branch] = ref
		}
		if len(path) > common+1 {
			return errors.New("CIDR stream skipped a path node")
		}
		if len(path) == common+1 {
			branch := path[len(path)-1]
			if branch > 1 {
				return errors.New("invalid CIDR branch")
			}
			frame := compressedFrame{depth: len(path) - 1, branch: branch, prefix: stack[len(stack)-1].prefix}
			if len(path) > 1 {
				index := len(path) - 2
				frame.prefix[index/8] |= branch << uint(7-index%8)
			}
			stack = append(stack, frame)
		}
		encoded, err := encodeValues(c, values)
		if err != nil {
			return err
		}
		size := uint64(len(encoded))
		frame := &stack[len(stack)-1]
		frame.valueOff, frame.valueLen = stats.values, size
		if output != nil && len(encoded) != 0 {
			if _, err := output.values.WriteAt(encoded, int64(stats.values)); err != nil {
				return err
			}
		}
		stats.values += size
		previous = append(previous[:0], path...)
		return nil
	})
	if err != nil {
		return compressedStats{}, err
	}
	for len(stack) > 1 {
		frame := stack[len(stack)-1]
		ref, err := finish(frame)
		if err != nil {
			return compressedStats{}, err
		}
		stack = stack[:len(stack)-1]
		stack[len(stack)-1].children[frame.branch] = ref
	}
	if _, err := finish(stack[0]); err != nil {
		return compressedStats{}, err
	}
	return stats, nil
}

func writeCompressedSegment[T comparable](path string, c codec.Codec[T], walk recordWalk[T]) (*segment[T], error) {
	// Spool the three areas in one traversal: merging and decoding old segments
	// twice costs CPU and allocations, especially during repeated compaction.
	var areas [3]*os.File
	for index := range areas {
		file, err := os.CreateTemp(filepath.Dir(path), ".cidr-area-*")
		if err != nil {
			return nil, err
		}
		areas[index] = file
		defer os.Remove(file.Name())
		defer file.Close()
	}
	output := compressedOutput{nodes: diskio.NewWriterAt(areas[0]), jumps: diskio.NewWriterAt(areas[1]), values: diskio.NewWriterAt(areas[2])}
	planned, err := compressedPass(walk, c, &output)
	if err != nil {
		return nil, err
	}
	for _, writer := range []*diskio.WriterAt{output.nodes, output.jumps, output.values} {
		if err := writer.Flush(); err != nil {
			return nil, err
		}
	}

	jumpOff := uint64(segmentHeaderSize) + planned.nodes*segmentNodeSize
	valueOff := jumpOff + planned.jumps*jumpSize
	total := valueOff + planned.values
	if jumpOff < segmentHeaderSize || valueOff < jumpOff || total < valueOff || total > ^uint64(0)>>1 {
		return nil, errors.New("CIDR segment size overflow")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".compressed-cidr-*")
	if err != nil {
		return nil, err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	defer file.Close()
	if err := file.Truncate(int64(total)); err != nil {
		return nil, err
	}
	var header [segmentHeaderSize]byte
	copy(header[:8], segmentMagic)
	binary.LittleEndian.PutUint32(header[8:], segmentVersion)
	binary.LittleEndian.PutUint64(header[16:], segmentHeaderSize)
	binary.LittleEndian.PutUint64(header[24:], planned.nodes)
	binary.LittleEndian.PutUint64(header[32:], valueOff)
	binary.LittleEndian.PutUint64(header[40:], planned.values)
	binary.LittleEndian.PutUint64(header[48:], planned.nodes-1)
	binary.LittleEndian.PutUint64(header[56:], jumpOff)
	if err := writeAll(file, header[:]); err != nil {
		return nil, err
	}
	buffer := make([]byte, 64<<10)
	sizes := [3]uint64{planned.nodes * segmentNodeSize, planned.jumps * jumpSize, planned.values}
	for index, area := range areas {
		if _, err := area.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		n, err := io.CopyBuffer(struct{ io.Writer }{file}, io.LimitReader(area, int64(sizes[index])), buffer)
		if err != nil {
			return nil, err
		}
		if uint64(n) != sizes[index] {
			return nil, io.ErrUnexpectedEOF
		}
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return openSegment[T](path, c)
}
