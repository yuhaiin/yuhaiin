// Package disk implements an optional disk-backed CIDR matcher.
//
// The default v2 CIDR matcher remains the in-memory implementation in the
// parent package. This package is used only when an explicit disk option is
// supplied to the v2 combined Trie.
package disk

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

const (
	defaultMemoryLimit         = 2 << 20
	segmentCompactionThreshold = 4
	absentChild                = ^uint64(0)
	netIPv4Bytes               = 4
)

// Option configures a disk CIDR matcher.
type Option func(*options)

type options struct {
	memoryLimit uint64
}

// WithMemoryLimit sets the approximate size of the mutable CIDR builder.
// Zero keeps the default limit.
func WithMemoryLimit(limit uint64) Option {
	return func(options *options) {
		if limit != 0 {
			options.memoryLimit = limit
		}
	}
}

type memoryNode[T comparable] struct {
	children [2]*memoryNode[T]
	values   []T
}

func newMemoryNode[T comparable]() *memoryNode[T] {
	return &memoryNode[T]{}
}

// Trie is an optional persistent binary prefix trie. Prefixes are stored as
// immutable segments after the mutable builder reaches its memory limit.
// Search returns marks from every matching prefix, from the shortest prefix
// to the most specific one, while deduplicating marks across segments.
type Trie[T comparable] struct {
	mu sync.RWMutex

	dir         string
	codec       codec.Codec[T]
	memoryLimit uint64
	root        *memoryNode[T]
	memoryUsed  uint64
	segments    []*segment[T]
	nextID      uint64
	closed      bool
}

// NewTrie opens or creates a disk CIDR matcher in dir.
func NewTrie[T comparable](dir string, c codec.Codec[T], opts ...Option) (*Trie[T], error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	configured := options{memoryLimit: defaultMemoryLimit}
	for _, option := range opts {
		option(&configured)
	}

	trie := &Trie[T]{
		dir:         dir,
		codec:       c,
		memoryLimit: configured.memoryLimit,
		root:        newMemoryNode[T](),
	}
	files, err := filepath.Glob(filepath.Join(dir, "segment-*.cidr"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, file := range files {
		segment, err := openSegment[T](file, c)
		if err != nil {
			_ = trie.closeSegments()
			return nil, err
		}
		trie.segments = append(trie.segments, segment)
		if id, ok := segmentID(file); ok && id >= trie.nextID {
			trie.nextID = id + 1
		}
	}
	if err := trie.compactIfNeededLocked(); err != nil {
		_ = trie.closeSegments()
		return nil, err
	}
	return trie, nil
}

// Dir returns the directory containing CIDR segment files.
func (t *Trie[T]) Dir() string { return t.dir }

// InsertCIDR adds a mark to a prefix. Duplicate marks at the same prefix are
// ignored, matching the in-memory CIDR matcher.
func (t *Trie[T]) InsertCIDR(prefix netip.Prefix, mark T) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || !prefix.IsValid() {
		return
	}
	prefix = prefix.Masked()
	t.insertLocked(prefix.Addr(), prefix.Bits(), mark)
	_ = t.flushIfNeededLocked()
}

// InsertIP adds a mark to an address prefix. Invalid mask sizes are ignored.
func (t *Trie[T]) InsertIP(addr netip.Addr, maskSize int, mark T) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || !addr.IsValid() || maskSize < 0 || maskSize > addr.BitLen() {
		return
	}
	t.insertLocked(addr, maskSize, mark)
	_ = t.flushIfNeededLocked()
}

// SearchIP returns all marks attached to prefixes containing addr.
func (t *Trie[T]) SearchIP(ip net.IP) []T {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		addr, ok := netip.AddrFromSlice(v4)
		if !ok {
			return nil
		}
		return t.searchAddr(addr)
	}
	addr, ok := netip.AddrFromSlice(ip.To16())
	if !ok {
		return nil
	}
	return t.searchAddr(addr)
}

// RemoveCIDR removes all marks attached to exactly prefix.
func (t *Trie[T]) RemoveCIDR(prefix netip.Prefix) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || !prefix.IsValid() {
		return
	}
	if err := t.materializeSegmentsLocked(); err != nil {
		return
	}
	prefix = prefix.Masked()
	removeNode(t.root, prefix.Addr(), prefix.Bits())
	t.memoryUsed = estimateTreeSize(t.root)
}

// RemoveIP removes all marks attached to exactly the address prefix.
func (t *Trie[T]) RemoveIP(addr netip.Addr, maskSize int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || !addr.IsValid() || maskSize < 0 || maskSize > addr.BitLen() {
		return
	}
	if err := t.materializeSegmentsLocked(); err != nil {
		return
	}
	removeNode(t.root, addr, maskSize)
	t.memoryUsed = estimateTreeSize(t.root)
}

// Sync flushes the mutable builder without changing the configured memory
// limit.
func (t *Trie[T]) Sync() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("trie is closed")
	}
	return t.flushLocked()
}

// Clear removes all CIDR segments and resets the matcher.
func (t *Trie[T]) Clear() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("trie is closed")
	}
	if err := t.closeSegments(); err != nil {
		return err
	}
	for _, file := range globSegments(t.dir) {
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	t.segments = nil
	t.nextID = 0
	t.root = newMemoryNode[T]()
	t.memoryUsed = 0
	return nil
}

// Close flushes the builder and releases all segment resources.
func (t *Trie[T]) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	flushErr := t.flushLocked()
	closeErr := t.closeSegments()
	t.closed = true
	return errors.Join(flushErr, closeErr)
}

func (t *Trie[T]) insertLocked(addr netip.Addr, bits int, value T) {
	node := t.root
	data := addr.AsSlice()
	family := uint8(1)
	if addr.Is4() {
		family = 0
	}
	if node.children[family] == nil {
		node.children[family] = newMemoryNode[T]()
		t.memoryUsed += 64
	}
	node = node.children[family]
	for index := range bits {
		branch := bitAt(data, index)
		if node.children[branch] == nil {
			node.children[branch] = newMemoryNode[T]()
			t.memoryUsed += 64
		}
		node = node.children[branch]
	}
	if slices.Contains(node.values, value) {
		return
	}
	node.values = append(node.values, value)
	t.memoryUsed += estimateValueSize(value)
}

func (t *Trie[T]) searchAddr(addr netip.Addr) []T {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return nil
	}
	data := addr.AsSlice()
	var result []T
	for _, segment := range t.segments {
		result = appendUnique(result, segment.search(data)...)
	}
	node := t.root.children[1]
	if addr.Is4() {
		node = t.root.children[0]
	}
	if node == nil {
		return result
	}
	result = appendUnique(result, node.values...)
	for index := 0; index < len(data)*8; index++ {
		node = node.children[bitAt(data, index)]
		if node == nil {
			break
		}
		result = appendUnique(result, node.values...)
	}
	return result
}

func bitAt(data []byte, index int) uint8 {
	return (data[index/8] >> uint(7-index%8)) & 1
}

func removeNode[T comparable](root *memoryNode[T], addr netip.Addr, bits int) {
	path := []*memoryNode[T]{root}
	node := root
	data := addr.AsSlice()
	family := uint8(1)
	if addr.Is4() {
		family = 0
	}
	node = node.children[family]
	if node == nil {
		return
	}
	path = append(path, node)
	for index := range bits {
		node = node.children[bitAt(data, index)]
		if node == nil {
			return
		}
		path = append(path, node)
	}
	node.values = nil
	for index := len(path) - 1; index > 0; index-- {
		current := path[index]
		if len(current.values) != 0 || current.children[0] != nil || current.children[1] != nil {
			break
		}
		parent := path[index-1]
		if parent.children[0] == current {
			parent.children[0] = nil
		} else if parent.children[1] == current {
			parent.children[1] = nil
		}
	}
}

func estimateValueSize[T comparable](value T) uint64 {
	if text, ok := any(value).(string); ok {
		return uint64(len(text) + 16)
	}
	return 64
}

func estimateTreeSize[T comparable](root *memoryNode[T]) uint64 {
	var size uint64
	var visit func(*memoryNode[T])
	visit = func(node *memoryNode[T]) {
		for _, child := range node.children {
			if child != nil {
				size += 64
				visit(child)
			}
		}
		for _, value := range node.values {
			size += estimateValueSize(value)
		}
	}
	visit(root)
	return size
}

func appendUnique[T comparable](dst []T, src ...T) []T {
	for _, value := range src {
		found := slices.Contains(dst, value)
		if !found {
			dst = append(dst, value)
		}
	}
	return dst
}

func (t *Trie[T]) flushIfNeededLocked() error {
	if t.memoryUsed < t.memoryLimit || isEmpty(t.root) {
		return nil
	}
	return t.flushLocked()
}

func isEmpty[T comparable](root *memoryNode[T]) bool {
	return root.children[0] == nil && root.children[1] == nil && len(root.values) == 0
}

func (t *Trie[T]) flushLocked() error {
	if isEmpty(t.root) {
		return nil
	}
	path := filepath.Join(t.dir, fmt.Sprintf("segment-%020d.cidr", t.nextID))
	segment, err := writeSegment(path, t.root, t.codec)
	if err != nil {
		return err
	}
	t.segments = append(t.segments, segment)
	t.nextID++
	t.root = newMemoryNode[T]()
	t.memoryUsed = 0
	return t.compactIfNeededLocked()
}

func (t *Trie[T]) compactIfNeededLocked() error {
	for len(t.segments) >= segmentCompactionThreshold {
		if err := t.compactOldestLocked(segmentCompactionThreshold); err != nil {
			return err
		}
	}
	return nil
}

func (t *Trie[T]) materializeSegmentsLocked() error {
	if len(t.segments) == 0 {
		return nil
	}
	root := newMemoryNode[T]()
	for _, segment := range t.segments {
		if err := segment.loadInto(root); err != nil {
			return err
		}
	}
	mergeNodes(root, t.root)
	if err := t.closeSegments(); err != nil {
		return err
	}
	for _, file := range globSegments(t.dir) {
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	t.segments = nil
	t.nextID = 0
	t.root = root
	t.memoryUsed = estimateTreeSize(root)
	return nil
}

func mergeNodes[T comparable](dst, src *memoryNode[T]) {
	dst.values = appendUnique(dst.values, src.values...)
	for branch, child := range src.children {
		if child == nil {
			continue
		}
		if dst.children[branch] == nil {
			dst.children[branch] = newMemoryNode[T]()
		}
		mergeNodes(dst.children[branch], child)
	}
}

func (t *Trie[T]) closeSegments() error {
	var err error
	for _, segment := range t.segments {
		err = errors.Join(err, segment.close())
	}
	return err
}
