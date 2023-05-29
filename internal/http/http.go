package simplehttp

import (
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/Asutorufa/yuhaiin/internal/http/bootstrap"
	tps "github.com/Asutorufa/yuhaiin/internal/http/templates"
	"github.com/Asutorufa/yuhaiin/pkg/app/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	config "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	snode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	sstatistic "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var debug func(*http.ServeMux)

type HttpServerOption struct {
	Mux         *http.ServeMux
	NodeServer  snode.NodeServer
	Subscribe   snode.SubscribeServer
	Connections sstatistic.ConnectionsServer
	Config      config.ConfigServiceServer
	Tag         snode.TagServer
	Shunt       *shunt.Shunt
}

func Httpserver(o HttpServerOption) {
	mux := o.Mux

	if debug != nil {
		debug(mux)
	}

	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte{}) })
	mux.Handle("/config", &handler{&configHandler{cf: o.Config}})
	mux.Handle("/conn", &handler{&conn{stt: o.Connections}})
	mux.Handle("/node", &handler{&nodeHandler{nm: o.NodeServer}})
	mux.Handle("/sub", &handler{&subHandler{nm: o.Subscribe}})
	mux.Handle("/group", &handler{&groupHandler{nm: o.NodeServer}})
	mux.Handle("/latency", &handler{&latencyHandler{nm: o.NodeServer}})
	mux.Handle("/tag", &handler{&tag{nm: o.NodeServer, ts: o.Tag, st: o.Shunt}})
	mux.Handle("/bootstrap/", http.StripPrefix("/bootstrap", http.FileServer(http.FS(bootstrap.Bootstrap))))
	mux.Handle("/", &handler{&rootHandler{nm: o.NodeServer}})
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
	defer r.Body.Close()

	log.Info("new http request", "method", r.Method, "url", r.URL)

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
