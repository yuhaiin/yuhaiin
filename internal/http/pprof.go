//go:build debug
// +build debug

package simplehttp

import (
	"net/http"
	"net/http/pprof"
	"runtime"
)

func init() {
	debug = func(mux *http.ServeMux) {
		// pprof
		runtime.MemProfileRate = 100 * 1024
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	}
}
