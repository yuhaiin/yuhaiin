package disk

import (
	"errors"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
)

// DefaultMemoryLimit is the approximate size of the mutable in-memory
// builder before it is written as an immutable segment.
const DefaultMemoryLimit = defaultMemoryLimit

// Option configures a disk Trie during construction.
type Option func(*options)

type options struct {
	memoryLimit uint64
}

// WithMemoryLimit changes the approximate memory limit of the active builder.
// A zero value keeps the default limit.
func WithMemoryLimit(limit uint64) Option {
	return func(options *options) {
		if limit != 0 {
			options.memoryLimit = limit
		}
	}
}

// Trie is a bounded-memory, append-only disk trie.
//
// New rules are collected in a small mutable tree and flushed to immutable
// segment files when the estimated builder size reaches the configured limit.
// Searches combine the mutable tree and all segments. Segment compaction is
// performed incrementally and uses temporary files rather than an in-memory
// copy of the complete index.
type Trie[T comparable] struct {
	mu sync.RWMutex

	dir           string
	codec         codec.Codec[T]
	memoryLimit   uint64
	separator     byte
	root          *memoryNode[T]
	memoryUsed    uint64
	segments      []*segment[T]
	nextSegmentID uint64
	closed        bool
}

// NewTrie opens or creates a disk-backed Trie in dir. Existing segment files
// are opened in numeric order so the newest values remain deterministic when
// duplicate values are merged during a search.
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
		separator:   '.',
		root:        newMemoryNode[T](),
	}
	files, err := filepath.Glob(filepath.Join(dir, "segment-*.mmap"))
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
		if id, ok := segmentID(file); ok && id >= trie.nextSegmentID {
			trie.nextSegmentID = id + 1
		}
	}
	if err := trie.compactIfNeededLocked(); err != nil {
		_ = trie.closeSegments()
		return nil, err
	}
	return trie, nil
}

// Dir returns the directory containing the segment files.
func (t *Trie[T]) Dir() string { return t.dir }

// SetSeparate changes the label separator used for subsequent operations.
// Call it before inserting or searching when using a non-domain key format.
func (t *Trie[T]) SetSeparate(separator byte) {
	t.mu.Lock()
	t.separator = separator
	t.mu.Unlock()
}

// Insert adds one value to a domain. Duplicate values at the same path are
// ignored, matching the behavior of the in-memory Trie implementation.
func (t *Trie[T]) Insert(domain string, value T) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkOpen(); err != nil {
		return err
	}
	t.insertMemoryLocked(splitDomain(domain, t.separator), value)
	return t.flushIfNeededLocked()
}

// Batch inserts all items while holding one write lock. The input sequence is
// consumed lazily, so callers do not need to materialize a large batch first.
func (t *Trie[T]) Batch(items iter.Seq2[string, T]) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkOpen(); err != nil {
		return err
	}
	for domain, value := range items {
		t.insertMemoryLocked(splitDomain(domain, t.separator), value)
		if err := t.flushIfNeededLocked(); err != nil {
			return err
		}
	}
	return nil
}

// Search returns all values matching domain, including exact and wildcard
// rules from both the active builder and immutable segments.
func (t *Trie[T]) Search(domain string) []T {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return nil
	}
	return t.searchLocked(splitDomain(domain, t.separator))
}

// Sync flushes the active builder. It is useful when another process should
// be able to reopen the index before this Trie is closed.
func (t *Trie[T]) Sync() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkOpen(); err != nil {
		return err
	}
	return t.flushLocked()
}

// Remove deletes one value. Since immutable segments are append-only, a
// removal materializes them into the bounded builder first; this is a rare
// maintenance path and keeps normal reads and writes simple.
func (t *Trie[T]) Remove(domain string, value T) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkOpen(); err != nil {
		return err
	}
	if len(t.segments) != 0 {
		if err := t.materializeSegmentsLocked(); err != nil {
			return err
		}
	}
	removeMemoryValue(t.root, splitDomain(domain, t.separator), value)
	t.memoryUsed = estimateTreeSize(t.root)
	return nil
}

// Clear removes all segment files and resets the Trie to an empty state.
func (t *Trie[T]) Clear() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkOpen(); err != nil {
		return err
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
	t.nextSegmentID = 0
	t.root = newMemoryNode[T]()
	t.memoryUsed = 0
	return nil
}

// Close flushes the active builder and closes all mapped/read-only segments.
// It is safe to call Close more than once.
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

func (t *Trie[T]) checkOpen() error {
	if t.closed {
		return errors.New("trie is closed")
	}
	return nil
}

func (t *Trie[T]) flushIfNeededLocked() error {
	if t.memoryUsed < t.memoryLimit || isEmptyMemoryNode(t.root) {
		return nil
	}
	return t.flushLocked()
}

func (t *Trie[T]) flushLocked() error {
	if isEmptyMemoryNode(t.root) {
		return nil
	}
	path := filepath.Join(t.dir, fmt.Sprintf("segment-%020d.mmap", t.nextSegmentID))
	segment, err := writeSegment(path, t.root, t.codec)
	if err != nil {
		return err
	}
	t.segments = append(t.segments, segment)
	t.nextSegmentID++
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

// materializeSegmentsLocked converts immutable segments back into the
// mutable representation so Remove can preserve exact value semantics.
func (t *Trie[T]) materializeSegmentsLocked() error {
	if len(t.segments) == 0 {
		return nil
	}
	root := newMemoryNode[T]()
	for _, segment := range t.segments {
		if err := segment.loadInto(root, nil); err != nil {
			return err
		}
	}
	mergeMemoryNodes(root, t.root)
	if err := t.closeSegments(); err != nil {
		return err
	}
	for _, file := range globSegments(t.dir) {
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	t.segments = nil
	t.nextSegmentID = 0
	t.root = root
	t.memoryUsed = estimateTreeSize(root)
	return nil
}

func (t *Trie[T]) closeSegments() error {
	var err error
	for _, segment := range t.segments {
		err = errors.Join(err, segment.close())
	}
	return err
}
