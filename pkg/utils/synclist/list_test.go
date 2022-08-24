package synclist

import "testing"

func TestSyncList(t *testing.T) {
	l := New[int]()

	l.PushFront(0)
	l.PushFront(-1)
	l.PushBack(1)

	b := l.Back()
	p := l.Front()

	for {
		if b == nil {
			break
		}
		t.Log(b.Value)
		b = b.Prev()
	}

	for {
		if p == nil {
			break
		}
		t.Log(p.Value)
		p = p.Next()
	}
}
