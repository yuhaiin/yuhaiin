package yerror

import (
	"github.com/Asutorufa/yuhaiin/pkg/log"
	protolog "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
)

func Must[T any](v T, err error) T {
	if err != nil {
		log.Output(2, protolog.LogLevel_error, err.Error())
		panic(err)
	}
	return v
}

func Ignore[T any](v T, err error) T {
	if err != nil {
		log.Output(2, protolog.LogLevel_warning, "ignore error: %v", err)
	}
	return v
}

func Ignore2[T, T1, T2 any](v T, _ T1, _ T2) T { return v }
