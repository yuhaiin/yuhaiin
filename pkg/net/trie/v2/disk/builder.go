package disk

import (
	"slices"
	"strings"
)

// memoryNode is the short-lived mutable representation used while a segment
// is being built. It is discarded after the segment is flushed.
type memoryNode[T comparable] struct {
	children map[string]*memoryNode[T]
	values   []T
}

func newMemoryNode[T comparable]() *memoryNode[T] {
	return &memoryNode[T]{children: make(map[string]*memoryNode[T])}
}

// splitDomain returns labels in reverse DNS order. For example,
// "www.example.com" becomes ["com", "example", "www"]. Reversing labels
// makes suffix matching a normal top-down Trie lookup.
func splitDomain(domain string, separator byte) []string {
	if domain == "" {
		return nil
	}
	labels := make([]string, 0, 4)
	end := len(domain)
	for {
		start := strings.LastIndexByte(domain[:end], separator) + 1
		labels = append(labels, domain[start:end])
		if start == 0 {
			break
		}
		end = start - 1
	}
	return labels
}

func (t *Trie[T]) insertMemoryLocked(labels []string, value T) {
	if len(labels) == 0 {
		return
	}
	node := t.root
	for _, label := range labels {
		child := node.children[label]
		if child == nil {
			child = newMemoryNode[T]()
			node.children[label] = child
			// This is deliberately conservative rather than an exact Go heap
			// measurement. It bounds the builder without adding reflection or
			// allocator instrumentation to the hot insertion path.
			t.memoryUsed += uint64(len(label)) + 48
		}
		node = child
	}
	if slices.Contains(node.values, value) {
		return
	}
	node.values = append(node.values, value)
	t.memoryUsed += estimateValueSize(value)
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
		for label, child := range node.children {
			size += uint64(len(label)) + 48
			visit(child)
		}
		for _, value := range node.values {
			size += estimateValueSize(value)
		}
	}
	visit(root)
	return size
}

func removeMemoryValue[T comparable](root *memoryNode[T], labels []string, value T) {
	path := []*memoryNode[T]{root}
	node := root
	for _, label := range labels {
		child := node.children[label]
		if child == nil {
			return
		}
		node = child
		path = append(path, node)
	}
	if index := slices.Index(node.values, value); index >= 0 {
		node.values = append(node.values[:index], node.values[index+1:]...)
	}
	for i := len(path) - 1; i > 0; i-- {
		if len(path[i].values) != 0 || len(path[i].children) != 0 {
			break
		}
		parent := path[i-1]
		for label, child := range parent.children {
			if child == path[i] {
				delete(parent.children, label)
				break
			}
		}
	}
}

func isEmptyMemoryNode[T comparable](root *memoryNode[T]) bool {
	return len(root.children) == 0 && len(root.values) == 0
}

// mergeMemoryNodes combines two Trie trees without introducing duplicates.
// It is used only by the rare Remove path, which must materialize immutable
// segments before applying an update.
func mergeMemoryNodes[T comparable](dst, src *memoryNode[T]) {
	for _, value := range src.values {
		if !slices.Contains(dst.values, value) {
			dst.values = append(dst.values, value)
		}
	}
	for label, srcChild := range src.children {
		dstChild := dst.children[label]
		if dstChild == nil {
			dstChild = newMemoryNode[T]()
			dst.children[label] = dstChild
		}
		mergeMemoryNodes(dstChild, srcChild)
	}
}

func insertMemoryNode[T comparable](root *memoryNode[T], labels []string, value T) {
	node := root
	for _, label := range labels {
		child := node.children[label]
		if child == nil {
			child = newMemoryNode[T]()
			node.children[label] = child
		}
		node = child
	}
	if !slices.Contains(node.values, value) {
		node.values = append(node.values, value)
	}
}
