package disk

import (
	"slices"
	"strings"
)

const missingNode = ^uint64(0)

type lookupPosition struct {
	id   uint64
	node segmentNode
}

// lookupCursor tracks the same logical path in every segment and the mutable
// builder. A failed advance leaves it unchanged, which preserves global
// exact-before-wildcard precedence across flush boundaries.
type lookupCursor[T comparable] struct {
	memory *memoryNode[T]
	parts  []*segment[T]
	nodes  []lookupPosition
	next   []lookupPosition
}

func (c *lookupCursor[T]) advance(label string) bool {
	var child *memoryNode[T]
	if c.memory != nil {
		child = c.memory.children[label]
	}
	found := child != nil
	for index, part := range c.parts {
		c.next[index].id = missingNode
		if c.nodes[index].id == missingNode {
			continue
		}
		if id, ok := part.childNode(c.nodes[index].id, c.nodes[index].node, label); ok {
			node, ok := part.node(id)
			if ok {
				c.next[index] = lookupPosition{id: id, node: node}
				found = true
			}
		}
	}
	if found {
		c.memory = child
		c.nodes, c.next = c.next, c.nodes
	}
	return found
}

func (c *lookupCursor[T]) appendValues(result []T, wildcard bool) []T {
	for index, part := range c.parts {
		position := c.nodes[index]
		if position.id == missingNode {
			continue
		}
		if wildcard {
			id, ok := part.childNode(position.id, position.node, "*")
			if !ok {
				continue
			}
			position.node, ok = part.node(id)
			if !ok {
				continue
			}
		}
		result = part.appendValues(result, position.node)
	}
	node := c.memory
	if wildcard && node != nil {
		node = node.children["*"]
	}
	if node != nil {
		result = appendUnique(result, node.values...)
	}
	return result
}

func (t *Trie[T]) searchLocked(domain string) []T {
	if domain == "" {
		return nil
	}
	// Compaction normally keeps fewer than four segments. Retain a fallback
	// for a trie whose preceding compaction failed, without allocating on the
	// normal read path.
	var positions [2 * segmentCompactionThreshold]lookupPosition
	storage := positions[:]
	if len(t.segments) > segmentCompactionThreshold {
		storage = make([]lookupPosition, 2*len(t.segments))
	}
	cursor := lookupCursor[T]{
		memory: t.root,
		parts:  t.segments,
		nodes:  storage[:len(t.segments)],
		next:   storage[len(t.segments) : 2*len(t.segments)],
	}
	for index, part := range t.segments {
		cursor.nodes[index] = lookupPosition{node: part.rootNode}
	}
	end := len(domain)
	start := strings.LastIndexByte(domain[:end], t.separator) + 1
	if !cursor.advance(domain[start:end]) {
		if !cursor.advance("*") {
			return nil
		}
		for !cursor.advance(domain[start:end]) {
			if start == 0 {
				return nil
			}
			end = start - 1
			start = strings.LastIndexByte(domain[:end], t.separator) + 1
		}
	}

	var result []T
	for start != 0 {
		result = cursor.appendValues(result, true)
		end = start - 1
		start = strings.LastIndexByte(domain[:end], t.separator) + 1
		if !cursor.advance(domain[start:end]) {
			return result
		}
	}
	result = cursor.appendValues(result, false)
	return cursor.appendValues(result, true)
}

func appendUnique[T comparable](dst []T, src ...T) []T {
	for _, value := range src {
		if !slices.Contains(dst, value) {
			dst = append(dst, value)
		}
	}
	return dst
}
