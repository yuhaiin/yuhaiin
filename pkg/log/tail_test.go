package log

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestTail(t *testing.T) {
	defer os.Remove("test.log")

	f, err := os.Create("test.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for i := range 10 {
			fmt.Fprintf(f, "test %d\n", i)
			time.Sleep(time.Second)
		}
		cancel()
	}()

	err = Tail(ctx, "test.log", func(line []string) {
		os.Stdout.Write([]byte(strings.Join(line, "\n")))
	})
	assert.NoError(t, err)
}
