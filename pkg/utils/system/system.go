package system

import (
	"runtime"
	_ "unsafe"
)

var Procs = func() int {
	procs := runtime.GOMAXPROCS(0)
	if procs < 4 {
		return 4
	}
	return procs
}()

//go:linkname now time.now
//go:noescape
func now() (sec int64, nsec int32, mono int64)

func NowUnix() int64 {
	sec, _, _ := now()
	return sec
}

func NowUnixNano() int64 {
	sec, nsec, _ := now()
	return sec*1e9 + int64(nsec)
}

func NowUnixMicro() int64 {
	sec, nsec, _ := now()
	return sec*1e6 + int64(nsec)/1e3
}
