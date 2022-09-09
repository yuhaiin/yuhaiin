package simplehttp

import (
	"html/template"
	"io"
	"net/http"
	"net/http/pprof"
	"strings"

	"github.com/Asutorufa/yuhaiin/internal/http/bootstrap"
	tps "github.com/Asutorufa/yuhaiin/internal/http/templates"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/grpc/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/grpc/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/grpc/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
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
	mux.Handle("/bootstrap/", http.StripPrefix("/bootstrap", http.FileServer(http.FS(bootstrap.Bootstrap))))
	mux.Handle("/", &handler{&rootHandler{nm: nm}})
}

var TPS = &templates{}

type templates struct {
	store syncmap.SyncMap[string, *template.Template]
}

func (t *templates) Execute(w io.Writer, data any, patterns ...string) error {
	key := strings.Join(patterns, "")
	z, ok := t.store.Load(key)
	if !ok {
		var err error
		z, err = template.ParseFS(tps.Pages, patterns...)
		if err != nil {
			return err
		}

		t.store.Store(key, z)
	}

	return z.Execute(w, data)
}

func (t *templates) BodyExecute(w io.Writer, data any, pattern string) error {
	return t.Execute(w, data, tps.FRAME, pattern)
}

type HTTP interface {
	Get(http.ResponseWriter, *http.Request) error
	Post(http.ResponseWriter, *http.Request) error
	Put(http.ResponseWriter, *http.Request) error
	Delete(http.ResponseWriter, *http.Request) error
	Patch(http.ResponseWriter, *http.Request) error
	Websocket(http.ResponseWriter, *http.Request) error
}

var _ http.Handler = (*handler)(nil)

type handler struct {
	HTTP
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Infoln(r.Method, r.URL)
	var err error
	switch r.Method {
	case http.MethodGet:
		if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
			strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
			err = h.Websocket(w, r)
		} else {
			err = h.Get(w, r)
		}
	case http.MethodPost:
		err = h.Post(w, r)
	case http.MethodPut:
		err = h.Put(w, r)
	case http.MethodDelete:
		err = h.Delete(w, r)
	case http.MethodPatch:
		err = h.Patch(w, r)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

var _ HTTP = (*emptyHTTP)(nil)

type emptyHTTP struct{}

func (emptyHTTP) Get(w http.ResponseWriter, r *http.Request) error       { return nil }
func (emptyHTTP) Post(w http.ResponseWriter, r *http.Request) error      { return nil }
func (emptyHTTP) Delete(w http.ResponseWriter, r *http.Request) error    { return nil }
func (emptyHTTP) Put(w http.ResponseWriter, r *http.Request) error       { return nil }
func (emptyHTTP) Patch(w http.ResponseWriter, r *http.Request) error     { return nil }
func (emptyHTTP) Websocket(w http.ResponseWriter, r *http.Request) error { return nil }
