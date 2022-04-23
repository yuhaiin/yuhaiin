package simplehttp

import (
	_ "embed"
	"fmt"
	"net/http"
	"net/http/pprof"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

//go:embed toast.html
var toastHTML []byte

func Httpserver(mux *http.ServeMux, nm node.NodeManagerServer, stt statistic.ConnectionsServer, cf config.ConfigDaoServer) {
	// pprof
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte{}) })

	initNode(mux, nm)
	initStatistic(mux, stt)
	initConfig(mux, cf)

}

func createHTML(s string) string {
	return fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>yuhaiin</title>
			<style>
				p {line-height:50%%;}
			</style>
		</head>
		<body>
			%s
			<hr/>
			<p>
				<a href="/">HOME</a>
				<a href="/group">GROUP</a>
				<a href="/sub">SUBSCRIBE</a>
				<a href="/conn/list">CONNECTIONS</a>
				<a href="/config">CONFIG</a>
				<a href="/debug/pprof">PPROF</a>
			</p>
		</body>
	</html>
	`, s)
}
