package log

import (
	"context"
	"os"
	"time"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

func Tail(ctx context.Context, path string, fn func(line string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scan := pool.GetBufioReader(f, 1024)
	defer pool.PutBufioReader(scan)

	for {
		line, _, err := scan.ReadLine()
		if err != nil {
			break
		}
		fn(unsafe.String(unsafe.SliceData(line), len(line)))
	}

	ticker := time.NewTicker(time.Second)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for {
				line, _, err := scan.ReadLine()
				if err != nil {
					break
				}
				fn(unsafe.String(unsafe.SliceData(line), len(line)))
			}
		}
	}
}
