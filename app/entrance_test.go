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

	//_recheck:
	t.Log("Check")
	select {
	case <-ctx.Done():
		t.Log("finished")
		//default:
		//	cancel()
		//	t.Log("re Check")
		//	goto _recheck
	}
}

func TestHash(t *testing.T) {
	a := md5.New()
	a.Write([]byte("aaaa"))
	t.Log(hex.EncodeToString(a.Sum(nil)))
	a.Write([]byte("aaaa"))
	t.Log(hex.EncodeToString(a.Sum(nil)))
}
