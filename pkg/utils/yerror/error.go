package yerror

import (
	"log/slog"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

func Must[T any](v T, err error) T {
	if err != nil {
		log.Output(1, slog.LevelError, "must error", "err", err)
		panic(err)
	}
	return v
}

func Ignore[T any](v T, err error) T {
	if err != nil {
		log.Output(1, slog.LevelWarn, "ignore error", "err", err)
	}
	return v
}

func Ignore2[T, T1, T2 any](v T, _ T1, _ T2) T { return v }
