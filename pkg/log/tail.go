package log

import (
	"context"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

func Tail(ctx context.Context, path string, fn func(line []string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scan := pool.GetBufioReader(f, 1024)
	defer pool.PutBufioReader(scan)

	dump := func() {
		var ret []string
		var failed bool
		for !failed {
			ret = ret[:0]

			for {
				line, _, err := scan.ReadLine()
				if err != nil {
					failed = true
					break
				}
				ret = append(ret, string(line))

				if len(ret) > 100 {
					break
				}
			}

			if len(ret) > 0 {
				fn(ret)
			}
		}
	}

	dump()

	ticker := time.NewTicker(time.Second)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			dump()
		}
	}
}
