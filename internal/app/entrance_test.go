package app

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"testing"
)

func TestCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	go func(ctx2 context.Context) {
		cancel()
	}(ctx)

	t.Log("Check")
	<-ctx.Done()
	t.Log("finished")
}

func TestHash(t *testing.T) {
	a := md5.New()
	a.Write([]byte("aaaa"))
	t.Log(hex.EncodeToString(a.Sum(nil)))
	a.Write([]byte("aaaa"))
	t.Log(hex.EncodeToString(a.Sum(nil)))
}

func TestLatency(t *testing.T) {
	e, err := NewEntrance()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	x := e.nodeManager.GetNowNode()
	t.Log(e.Latency(x.NGroup, x.NName))
}
