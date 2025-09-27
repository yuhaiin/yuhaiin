package log

import (
	"context"
	"os"
	"testing"
	"time"

	protolog "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/proto"
)

func TestTail(t *testing.T) {
	ctr := NewController()
	defer func() {
		if err := ctr.Close(); err != nil {
			t.Error(err)
		}
	}()

	OutputStderr.Store(false)
	ctr.Set(protolog.Logcat_builder{
		Save:  proto.Bool(true),
		Level: protolog.LogLevel_debug.Enum(),
	}.Build(), "test.log")

	defer func() {
		if err := os.Remove("test.log"); err != nil {
			t.Error(err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for i := range 10 {
			Info("test", "i", i)
			time.Sleep(time.Second)
		}
		cancel()
	}()

	err := ctr.Tail(ctx, func(line []string) {
		t.Log(line)
	})
	assert.NoError(t, err)
}
