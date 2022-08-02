package yerror

import (
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func Must[T any](v T, err error) T {
	if err != nil {
		log.Output(2, config.Logcat_error, err.Error())
		panic(err)
	}
	return v
}

func Ignore[T any](v T, err error) T {
	if err != nil {
		log.Output(2, config.Logcat_warning, "ignore error: %v", err)
	}
	return v
}
