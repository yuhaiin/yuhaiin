package relay

import (
	"fmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"io"
	"testing"
)

func BenchmarkPipeRelay(b *testing.B) {
	for _, size := range []int{64, 16384, 65536} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			writer, reader := pipe.Pipe()
			defer writer.Close()
			defer reader.Close()
			done := make(chan error, 1)
			go func() { _, err := Copy(io.Discard, reader); done <- err }()
			payload := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				if _, err := writer.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
			_ = writer.CloseWrite()
			if err := <-done; err != nil {
				b.Fatal(err)
			}
		})
	}
}
