package disk

import "slices"

// searchLocked follows the same suffix/wildcard precedence as the existing
// domain Trie. It consults the active builder and immutable segments through
// hasChild and valuesAt, so a rule can be split across flush boundaries.
func (t *Trie[T]) searchLocked(labels []string) []T {
	if len(labels) == 0 {
		return nil
	}
	var result []T
	path := make([]string, 0, len(labels)+1)
	matched := 0

	if t.hasChild(path, labels[0]) {
		path = append(path, labels[0])
		goto descend
	}
	if !t.hasChild(path, "*") {
		return nil
	}
	path = append(path, "*")
	for index, label := range labels {
		if t.hasChild(path, label) {
			path = append(path, label)
			matched = index
			goto descend
		}
	}
	return nil

descend:
	for _, label := range labels[matched+1:] {
		if t.hasChild(path, "*") {
			result = appendUnique(result, t.valuesAt(appendPath(path, "*"))...)
		}
		next := appendPath(path, label)
		if !t.hasChild(path, label) {
			return result
		}
		path = next
	}

	result = appendUnique(result, t.valuesAt(path)...)
	if t.hasChild(path, "*") {
		result = appendUnique(result, t.valuesAt(appendPath(path, "*"))...)
	}
	return result
}

func appendPath(path []string, label string) []string {
	next := make([]string, len(path)+1)
	copy(next, path)
	next[len(path)] = label
	return next
}

func appendUnique[T comparable](dst []T, src ...T) []T {
	for _, value := range src {
		if !slices.Contains(dst, value) {
			dst = append(dst, value)
		}
	}
	return dst
}

func (t *Trie[T]) hasChild(path []string, label string) bool {
	if memoryChildExists(t.root, path, label) {
		return true
	}
	for _, segment := range t.segments {
		if !segmentMayContainPath(segment, path, label) {
			continue
		}
		if segment.childPath(path, label) {
			return true
		}
	}
	return false
}

func (t *Trie[T]) valuesAt(path []string) []T {
	var result []T
	for _, segment := range t.segments {
		if len(path) != 0 && !segment.mayContainRoot(path[0]) {
			continue
		}
		result = appendUnique(result, segment.valuesPath(path)...)
	}
	result = appendUnique(result, memoryValuesAt(t.root, path)...)
	return result
}

func segmentMayContainPath[T comparable](segment *segment[T], path []string, label string) bool {
	if len(path) == 0 {
		return segment.mayContainRoot(label)
	}
	return segment.mayContainRoot(path[0])
}

func memoryChildExists[T comparable](root *memoryNode[T], path []string, label string) bool {
	node := root
	for _, part := range path {
		node = node.children[part]
		if node == nil {
			return false
		}
	}
	_, ok := node.children[label]
	return ok
}

func memoryValuesAt[T comparable](root *memoryNode[T], path []string) []T {
	node := root
	for _, part := range path {
		node = node.children[part]
		if node == nil {
			return nil
		}
	}
	return node.values
}
