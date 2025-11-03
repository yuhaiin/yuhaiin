package list

import "testing"

func TestSyncList(t *testing.T) {
	l := NewSyncList[int]()

	l.PushFront(0)
	l.PushFront(-1)
	l.PushBack(1)

	b := l.Back()
	p := l.Front()

	for b != nil {
		t.Log(b.Value)
		b = b.Prev()
	}

	for p != nil {
		t.Log(p.Value)
		p = p.Next()
	}
}
