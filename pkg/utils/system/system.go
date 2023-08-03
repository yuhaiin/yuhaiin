package system

import "runtime"

var Procs = func() int {
	procs := runtime.GOMAXPROCS(0)
	if procs < 4 {
		return 4
	}
	return procs
}()
