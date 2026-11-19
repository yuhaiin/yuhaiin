package processpath

import (
	"hash/maphash"
	"math/bits"
	"slices"
	"strings"
	"unsafe"
)

// Index maps process paths to the lists whose entries match them. It is
// immutable once built and safe for concurrent use; a configuration change
// builds a new Index and swaps it in.
//
// Exact entries are a single map lookup on the canonical path. Each glob is
// filed under one necessary condition, its most selective key: a literal
// component (or the literal prefix or suffix of a wildcard component) either
// at a fixed depth below its root or, after a **, at any depth. A lookup
// probes the keys the path actually contains, so only globs sharing a key
// with the path are evaluated. Globs without any literal text are evaluated
// on every lookup; Stats reports how many there are.
type Index struct {
	flavor     Flavor
	exact      map[string][]string
	globs      []indexedGlob
	roots      map[string]int32
	tables     [keyKinds]keyTable
	seed       uint64
	prefixLens []int
	suffixLens []int
	fallback   []int32
	lists      []string
	stats      Stats
}

type indexedGlob struct {
	segs  []segment
	root  int32 // -1: any root
	min   int   // components the pattern needs at least
	lists []string
}

type keyKind uint8

const (
	keyLiteral keyKind = iota
	keyPrefix
	keySuffix
	keyKinds
)

type indexKey struct {
	text  string
	depth int32 // -1: any depth
	kind  keyKind
}

// keyTable holds the globs filed under keys of one kind: an open-addressing
// hash table at most half full, so that a probe costs one hash and usually
// one slot read, and a component that is no key is rejected on its hash.
//
// A Bloom filter of 16 bits per key sits in front of the table: it is small
// enough to stay in the L1 cache and rejects most components that are no key,
// such as "usr" or "bin", without touching the table.
type keyTable struct {
	bloom     []uint64
	bloomMask uint64
	slots     []keySlot
	mask      uint64
}

func (t *keyTable) mayContain(h uint64) bool {
	a, b := h&t.bloomMask, (h>>32)&t.bloomMask
	return t.bloom[a>>6]&(1<<(a&63)) != 0 && t.bloom[b>>6]&(1<<(b&63)) != 0
}

// keyHash mixes eight bytes at a time. Collisions only cost an extra
// comparison; the key text is always compared.
func keyHash(seed uint64, s string) uint64 {
	h := seed ^ uint64(len(s))*0x9e3779b97f4a7c15
	for len(s) >= 8 {
		h = (h ^ load64(s)) * 0xff51afd7ed558ccd
		h ^= h >> 32
		s = s[8:]
	}
	var tail uint64
	for i := len(s) - 1; i >= 0; i-- {
		tail = tail<<8 | uint64(s[i])
	}
	h = (h ^ tail) * 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 29
	return h
}

func load64(s string) uint64 {
	_ = s[7]
	return uint64(s[0]) | uint64(s[1])<<8 | uint64(s[2])<<16 | uint64(s[3])<<24 |
		uint64(s[4])<<32 | uint64(s[5])<<40 | uint64(s[6])<<48 | uint64(s[7])<<56
}

type keySlot struct {
	hash    uint64
	text    string
	buckets []bucket // nil: empty slot
}

// bucket is the globs filed under one key text at one depth (-1: any).
type bucket struct {
	depth int32
	globs []int32
}

func (t *keyTable) find(h uint64, text string) []bucket {
	for i := h & t.mask; ; i = (i + 1) & t.mask {
		slot := &t.slots[i]
		if slot.buckets == nil {
			return nil
		}
		if slot.hash == h && slot.text == text {
			return slot.buckets
		}
	}
}

func (t *keyTable) insert(h uint64, text string, b bucket) {
	a, c := h&t.bloomMask, (h>>32)&t.bloomMask
	t.bloom[a>>6] |= 1 << (a & 63)
	t.bloom[c>>6] |= 1 << (c & 63)
	for i := h & t.mask; ; i = (i + 1) & t.mask {
		slot := &t.slots[i]
		if slot.buckets == nil {
			*slot = keySlot{hash: h, text: text, buckets: []bucket{b}}
			return
		}
		if slot.hash == h && slot.text == text {
			slot.buckets = append(slot.buckets, b)
			return
		}
	}
}

// keyLengths are the lengths prefix and suffix keys are cut to, which
// bounds the probes per component to len(keyLengths) per kind.
var keyLengths = []int{1, 2, 3, 4, 6, 8, 12, 16, 24, 32}

func cutKeyLength(n int) int {
	cut := 0
	for _, length := range keyLengths {
		if length <= n {
			cut = length
		}
	}
	return cut
}

// Stats describes a built index.
type Stats struct {
	Entries     int     // entries added, duplicates included
	Exact       int     // distinct exact paths and names
	Globs       int     // distinct compiled globs
	Foreign     int     // entries for the other platform family
	Lists       int     // registered lists
	Buckets     int     // glob index keys
	Fallback    int     // globs evaluated on every lookup
	MaxBucket   int     // largest number of globs under one key
	AvgGlobLen  float64 // average segments per glob
	AvgGlobRefs float64 // average lists per glob
	PrefixLens  int     // distinct prefix key lengths probed
	SuffixLens  int     // distinct suffix key lengths probed
}

// Builder collects entries for an Index.
type Builder struct {
	flavor  Flavor
	exact   map[string][]string
	globs   []builderGlob
	byKey   map[string]int
	lists   []string
	listSet map[string]struct{}
	stats   Stats
}

type builderGlob struct {
	pattern Pattern
	lists   []string
}

// NewBuilder starts an index for paths of flavor f.
func NewBuilder(f Flavor) *Builder {
	return &Builder{flavor: f, exact: map[string][]string{}, byKey: map[string]int{}, listSet: map[string]struct{}{}}
}

// Register records list even if it ends up with no usable entries.
func (b *Builder) Register(list string) {
	if _, ok := b.listSet[list]; !ok {
		b.listSet[list] = struct{}{}
		b.lists = append(b.lists, list)
	}
}

// Add compiles entry and files it under list. An invalid entry is reported
// and skipped; the builder stays usable.
func (b *Builder) Add(entry, list string) (Kind, error) {
	b.Register(list)
	pattern, err := b.flavor.Compile(entry)
	if err != nil {
		return 0, err
	}
	b.stats.Entries++
	switch pattern.kind {
	case KindForeign:
		b.stats.Foreign++
	case KindExact:
		b.exact[pattern.key] = appendList(b.exact[pattern.key], list)
	case KindGlob:
		i, ok := b.byKey[pattern.key]
		if !ok {
			i = len(b.globs)
			b.byKey[pattern.key] = i
			b.globs = append(b.globs, builderGlob{pattern: pattern})
		}
		b.globs[i].lists = appendList(b.globs[i].lists, list)
	}
	return pattern.kind, nil
}

func appendList(lists []string, list string) []string {
	if slices.Contains(lists, list) {
		return lists
	}
	return append(lists, list)
}

// candidateKeys returns every necessary-condition key of a glob.
func candidateKeys(p Pattern) []indexKey {
	var keys []indexKey
	depth := int32(0)
	for _, seg := range p.segs {
		if seg.kind == segAny {
			depth = -1
			continue
		}
		if p.floating {
			depth = -1
		}
		switch seg.kind {
		case segLiteral:
			keys = append(keys, indexKey{text: seg.text, depth: depth, kind: keyLiteral})
		case segWild:
			if i := strings.IndexAny(seg.text, "*?"); i > 0 {
				keys = append(keys, indexKey{text: seg.text[:cutKeyLength(i)], depth: depth, kind: keyPrefix})
			}
			if i := strings.LastIndexAny(seg.text, "*?"); i < len(seg.text)-1 {
				suffix := seg.text[i+1:]
				keys = append(keys, indexKey{text: suffix[len(suffix)-cutKeyLength(len(suffix)):], depth: depth, kind: keySuffix})
			}
		}
		if depth >= 0 {
			depth++
		}
	}
	return keys
}

// betterKey prefers the rarer key; on a tie a fixed depth, a whole literal,
// then longer text.
func betterKey(a indexKey, ac int, b indexKey, bc int) bool {
	if ac != bc {
		return ac < bc
	}
	if (a.depth >= 0) != (b.depth >= 0) {
		return a.depth >= 0
	}
	if (a.kind == keyLiteral) != (b.kind == keyLiteral) {
		return a.kind == keyLiteral
	}
	return len(a.text) > len(b.text)
}

// Build finishes the index. The builder must not be used afterwards.
func (b *Builder) Build() *Index {
	ix := &Index{
		flavor: b.flavor,
		exact:  b.exact,
		roots:  map[string]int32{},
		seed:   maphash.Comparable(maphash.MakeSeed(), 0) | 1,
		lists:  b.lists,
		stats:  b.stats,
	}
	chosen := map[indexKey][]int32{}
	keys := make([][]indexKey, len(b.globs))
	counts := map[indexKey]int{}
	for i, glob := range b.globs {
		keys[i] = candidateKeys(glob.pattern)
		for _, key := range keys[i] {
			counts[key]++
		}
	}
	prefixLens, suffixLens := map[int]bool{}, map[int]bool{}
	var segments, refs int
	ix.globs = make([]indexedGlob, len(b.globs))
	for i, glob := range b.globs {
		p := glob.pattern
		root := int32(-1)
		if !p.floating {
			id, ok := ix.roots[p.root]
			if !ok {
				id = int32(len(ix.roots))
				ix.roots[p.root] = id
			}
			root = id
		}
		minimum := 0
		for _, seg := range p.segs {
			if seg.kind != segAny {
				minimum++
			}
		}
		ix.globs[i] = indexedGlob{segs: p.segs, root: root, min: minimum, lists: glob.lists}
		segments += len(p.segs)
		refs += len(glob.lists)

		if len(keys[i]) == 0 {
			ix.fallback = append(ix.fallback, int32(i))
			continue
		}
		best := keys[i][0]
		for _, key := range keys[i][1:] {
			if betterKey(key, counts[key], best, counts[best]) {
				best = key
			}
		}
		chosen[best] = append(chosen[best], int32(i))
		switch best.kind {
		case keyPrefix:
			prefixLens[len(best.text)] = true
		case keySuffix:
			suffixLens[len(best.text)] = true
		}
	}
	for _, length := range keyLengths {
		if prefixLens[length] {
			ix.prefixLens = append(ix.prefixLens, length)
		}
		if suffixLens[length] {
			ix.suffixLens = append(ix.suffixLens, length)
		}
	}
	var texts [keyKinds]map[string]bool
	for key := range chosen {
		if texts[key.kind] == nil {
			texts[key.kind] = map[string]bool{}
		}
		texts[key.kind][key.text] = true
	}
	for kind := range keyKinds {
		if len(texts[kind]) == 0 {
			continue
		}
		size := max(16, 1<<bits.Len(uint(len(texts[kind])*2-1)))
		bloom := max(64, 1<<bits.Len(uint(len(texts[kind])*16-1)))
		ix.tables[kind] = keyTable{bloom: make([]uint64, bloom/64), bloomMask: uint64(bloom - 1), slots: make([]keySlot, size), mask: uint64(size - 1)}
	}
	for key, globs := range chosen {
		ix.tables[key.kind].insert(keyHash(ix.seed, key.text), key.text, bucket{depth: key.depth, globs: globs})
		ix.stats.MaxBucket = max(ix.stats.MaxBucket, len(globs))
	}
	ix.stats.Buckets = len(chosen)
	ix.stats.Exact = len(ix.exact)
	ix.stats.Globs = len(ix.globs)
	ix.stats.Lists = len(ix.lists)
	ix.stats.Fallback = len(ix.fallback)
	if len(ix.globs) > 0 {
		ix.stats.AvgGlobLen = float64(segments) / float64(len(ix.globs))
		ix.stats.AvgGlobRefs = float64(refs) / float64(len(ix.globs))
	}
	ix.stats.PrefixLens = len(ix.prefixLens)
	ix.stats.SuffixLens = len(ix.suffixLens)
	*b = Builder{}
	return ix
}

// Empty reports whether no entry can match on this platform.
func (ix *Index) Empty() bool { return ix == nil || len(ix.exact) == 0 && len(ix.globs) == 0 }

// Lists returns the registered lists in registration order.
func (ix *Index) Lists() []string {
	if ix == nil {
		return nil
	}
	return ix.lists
}

// Stats describes the index.
func (ix *Index) Stats() Stats {
	if ix == nil {
		return Stats{}
	}
	return ix.stats
}

// matchSet accumulates list IDs, sharing the index's slices until a second
// source adds an ID the first did not have.
type matchSet struct {
	ids   []string
	owned bool
}

func (m *matchSet) add(ids []string) {
	if len(m.ids) == 0 {
		m.ids = ids
		return
	}
	for _, id := range ids {
		if slices.Contains(m.ids, id) {
			continue
		}
		if !m.owned {
			m.ids = append(make([]string, 0, len(m.ids)+len(ids)), m.ids...)
			m.owned = true
		}
		m.ids = append(m.ids, id)
	}
}

// Match returns the lists matching path. The result is shared and must not
// be modified.
func (ix *Index) Match(path string) []string {
	if ix == nil || path == "" {
		return nil
	}
	if len(ix.globs) == 0 && !ix.flavor.windows {
		// Exact entries only. Keys are canonical, so a raw hit is a hit on
		// the canonical path and needs no normalization.
		if ids, ok := ix.exact[path]; ok {
			return ids
		}
	}
	var buf [512]byte
	n, abs := ix.flavor.normalize(buf[:0], path)
	if !abs {
		return ix.exact[path]
	}
	if len(ix.globs) == 0 {
		if len(n.s) == len(path) && unsafe.StringData(n.s) == unsafe.StringData(path) {
			return nil // already canonical: looked up above
		}
		return ix.exact[n.s]
	}
	var set matchSet
	set.add(ix.exact[n.s])

	var spanBuf [64]span
	l := lookup{
		ix:         ix,
		components: components{s: n.s, spans: splitSpans(spanBuf[:0], n.s, n.root+1)},
		rootText:   n.rootString(),
		root:       rootUnknown,
	}
	for depth := range l.components.spans {
		component := l.components.at(depth)
		l.probe(&set, keyLiteral, component, depth)
		for _, length := range ix.prefixLens {
			if length > len(component) {
				break
			}
			l.probe(&set, keyPrefix, component[:length], depth)
		}
		for _, length := range ix.suffixLens {
			if length > len(component) {
				break
			}
			l.probe(&set, keySuffix, component[len(component)-length:], depth)
		}
	}
	for _, i := range ix.fallback {
		l.try(&set, i)
	}
	return set.ids
}

const (
	rootUnknown = -3 // not looked up yet
	rootNone    = -2 // no anchored glob uses this root
)

// lookup is the state of one Match call. The result set is kept apart:
// sharing a struct with it would make the stack buffers escape.
type lookup struct {
	ix         *Index
	components components
	rootText   string
	root       int32
}

// probe evaluates the globs filed under text at depth and at any depth.
func (l *lookup) probe(set *matchSet, kind keyKind, text string, depth int) {
	table := &l.ix.tables[kind]
	if table.slots == nil {
		return
	}
	h := keyHash(l.ix.seed, text)
	if !table.mayContain(h) {
		return
	}
	for _, bucket := range table.find(h, text) {
		if bucket.depth < 0 || int(bucket.depth) == depth {
			for _, i := range bucket.globs {
				l.try(set, i)
			}
		}
	}
}

func (l *lookup) try(set *matchSet, i int32) {
	glob := &l.ix.globs[i]
	if len(l.components.spans) < glob.min {
		return
	}
	if glob.root >= 0 {
		if l.root == rootUnknown {
			l.root = rootNone
			if id, ok := l.ix.roots[l.rootText]; ok {
				l.root = id
			}
		}
		if glob.root != l.root {
			return
		}
	}
	if matchSegments(glob.segs, l.components) {
		set.add(glob.lists)
	}
}

// span locates one component; components are kept as offsets so that the
// canonical path, which may live in a stack buffer, never escapes.
type span struct{ start, end int32 }

type components struct {
	s     string
	spans []span
}

func (c components) at(i int) string { return c.s[c.spans[i].start:c.spans[i].end] }

// splitSpans appends the spans of the "/"-separated components of s[from:].
func splitSpans(spans []span, s string, from int) []span {
	start := from
	for i := from; i < len(s); i++ {
		if s[i] == '/' {
			spans = append(spans, span{int32(start), int32(i)})
			start = i + 1
		}
	}
	if start < len(s) {
		spans = append(spans, span{int32(start), int32(len(s))})
	}
	return spans
}
