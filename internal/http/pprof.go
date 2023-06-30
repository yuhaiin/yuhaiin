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
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
}
