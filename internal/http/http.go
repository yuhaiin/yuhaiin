package simplehttp

import (
	_ "embed"
	"fmt"
	"net/http"
	"net/http/pprof"

	"github.com/Asutorufa/yuhaiin/pkg/protos/grpc/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/grpc/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/grpc/statistic"
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

//go:embed http.js
var metaJS []byte

// <meta charset="UTF-8">
func createHTML(s string) string {
	return fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
		<head>
			<title>yuhaiin</title>
			<style></style>
			<script>%s</script>
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
	`, metaJS, s)
}
