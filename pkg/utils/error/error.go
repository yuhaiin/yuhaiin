package yerror

import (
	"log"
)

func Must[T any](v T, err error) T {
	if err != nil {
		log.Output(2, err.Error())
		panic(err)
	}
	return v
}

func To[T any](err error) (t T, _ bool) {
	for {
		if t, ok := err.(T); ok {
			return t, ok
		}

		if er, ok := err.(interface{ Unwrap() error }); ok {
			if err = er.Unwrap(); err == nil {
				return
			}
		}
	}
}
