package error

import "log"

func Must[T any](v T, err error) T {
	if err != nil {
		log.Output(2, err.Error())
		panic(err)
	}
	return v
}
