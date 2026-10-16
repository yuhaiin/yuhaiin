package lightweight

import "sync"

// Cache links live inside charged descriptors. Empty classes allocate no
// backing arrays; all classes still share the pool's byte admission budget.
const maxCachedObjects = 4096

type bufferFreeList struct {
	mu    sync.Mutex
	head  *ownedBuffer
	count int
}

func (f *bufferFreeList) available() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.head != nil
}
func (f *bufferFreeList) pop() *ownedBuffer {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := f.head
	if b != nil {
		f.head = b.cacheNext
		b.cacheNext = nil
		f.count--
	}
	return b
}
func (f *bufferFreeList) push(b *ownedBuffer) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.count == maxCachedObjects {
		return false
	}
	b.cacheNext = f.head
	f.head = b
	f.count++
	return true
}

type segmentFreeList struct {
	mu    sync.Mutex
	head  *sendSegment
	count int
}

func (f *segmentFreeList) pop() *sendSegment {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.head
	if v != nil {
		f.head = v.cacheNext
		v.cacheNext = nil
		f.count--
	}
	return v
}
func (f *segmentFreeList) push(v *sendSegment) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.count == maxCachedObjects {
		return false
	}
	v.cacheNext = f.head
	f.head = v
	f.count++
	return true
}
