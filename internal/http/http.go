package simplehttp

import (
	"fmt"
	"net/http"
	"net/http/pprof"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/protos/grpc/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/grpc/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/grpc/statistic"
)

func Httpserver(mux *http.ServeMux, nm node.NodeManagerServer, stt statistic.ConnectionsServer, cf config.ConfigDaoServer) {
	// pprof
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte{}) })

	mux.Handle("/config", &handler{&configHandler{cf: cf}})
	mux.Handle("/conn", &handler{&conn{stt: stt}})
	mux.Handle("/node", &handler{&nodeHandler{nm: nm}})
	mux.Handle("/sub", &handler{&subHandler{nm: nm}})
	mux.Handle("/group", &handler{&groupHandler{nm: nm}})
	mux.Handle("/latency", &handler{&latencyHandler{nm: nm}})
	mux.Handle("/", &handler{&rootHandler{nm: nm}})
}

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
				<a href="/conn">CONNECTIONS</a>
				<a href="/config">CONFIG</a>
				<a href="/debug/pprof">PPROF</a>
			</p>
		</body>
	</html>
	`, metaJS, s)
}

type HTTP interface {
	Get(http.ResponseWriter, *http.Request)
	Post(http.ResponseWriter, *http.Request)
	Put(http.ResponseWriter, *http.Request)
	Delete(http.ResponseWriter, *http.Request)
	Patch(http.ResponseWriter, *http.Request)
	Websocket(http.ResponseWriter, *http.Request)
}

var _ http.Handler = (*handler)(nil)

type handler struct {
	HTTP
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
			strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
			h.Websocket(w, r)
		} else {
			h.Get(w, r)
		}
	case http.MethodPost:
		h.Post(w, r)
	case http.MethodPut:
		h.Put(w, r)
	case http.MethodDelete:
		h.Delete(w, r)
	case http.MethodPatch:
		h.Patch(w, r)
	}
}

var _ HTTP = (*emptyHTTP)(nil)

type emptyHTTP struct{}

func (emptyHTTP) Get(w http.ResponseWriter, r *http.Request)       {}
func (emptyHTTP) Post(w http.ResponseWriter, r *http.Request)      {}
func (emptyHTTP) Delete(w http.ResponseWriter, r *http.Request)    {}
func (emptyHTTP) Put(w http.ResponseWriter, r *http.Request)       {}
func (emptyHTTP) Patch(w http.ResponseWriter, r *http.Request)     {}
func (emptyHTTP) Websocket(w http.ResponseWriter, r *http.Request) {}
