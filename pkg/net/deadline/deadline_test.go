package deadline

import (
	"testing"
	"time"
)

func TestDeadline(t *testing.T) {
	nd := New()

	pd := NewPipe()

	go func() {
		now := time.Now()
		<-nd.ctx.Done()
		t.Log("done", time.Since(now))
	}()

	go func() {
		now := time.Now()
		<-pd.WriteContext().Done()
		t.Log("write done", time.Since(now))
	}()

	go func() {
		now := time.Now()
		<-pd.ReadContext().Done()
		t.Log("read done", time.Since(now))
	}()

	pd.SetDeadline(time.Now().Add(2 * time.Second))
	nd.SetDeadline(time.Now().Add(3 * time.Second))

	<-nd.Context().Done()
	<-pd.WriteContext().Done()
	<-pd.ReadContext().Done()

	time.Sleep(time.Second)
}
