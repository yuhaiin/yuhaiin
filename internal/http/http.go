package simplehttp

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/components/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	config "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	snode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	sstatistic "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"golang.org/x/exp/slog"
)

//go:embed build
var front embed.FS

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

	root, _ := fs.Sub(front, "build")
	fs := http.FileServer(http.FS(root))

	handlers := Handler{}

	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug("http new request", slog.String("method", r.Method), slog.String("path", r.URL.String()))
		if strings.HasPrefix(r.URL.Path, "/yuhaiin") {
			r.URL.Path = "/"
		}

		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/static") {
			fs.ServeHTTP(w, r)
		} else {
			handlers.ServeHTTP(w, r)
		}
	}))

	conn := &conn{stt: o.Connections}
	group := &groupHandler{nm: o.NodeServer}
	sub := &subHandler{nm: o.Subscribe}
	tag := &tag{nm: o.NodeServer, ts: o.Tag, st: o.Shunt}
	config := &configHandler{cf: o.Config}
	node := &nodeHandler{nm: o.NodeServer}
	rh := &rootHandler{nm: o.NodeServer}
	latency := &latencyHandler{nm: o.NodeServer}

	var routes = map[string]map[string]func(http.ResponseWriter, *http.Request) error{
		"GET": {
			"/grouplist":   group.GroupList,
			"/group":       group.Get,
			"/sublist":     sub.GetLinkList,
			"/taglist":     tag.List,
			"/config/json": config.Config,
			"/node/now":    rh.NodeNow,
			"/node":        node.Get,
			"/latency":     latency.Get,
		},
		"POST": {
			"/config": config.Post,
			"/node":   node.Post,
			"/sub":    sub.Post,
			"/tag":    tag.Post,
		},
		"DELETE": {
			"/conn": conn.Delete,
			"/node": node.Delete,
			"/sub":  sub.Delete,
			"/tag":  tag.Delete,
		},
		"PUT": {
			"/node": node.Put,
		},
		"PATCH": {
			"/sub": sub.Patch,
		},
		"WS": {
			"/conn": conn.Websocket,
		},
	}

	for method, v := range routes {
		for path, handler := range v {
			handlers.Handle(method, path, handler)
		}
	}
}

type Handler struct {
	handlers map[string]map[string]func(http.ResponseWriter, *http.Request) error
}

func (h *Handler) Handle(method, pattern string, handler func(http.ResponseWriter, *http.Request) error) {
	if h.handlers == nil {
		h.handlers = make(map[string]map[string]func(http.ResponseWriter, *http.Request) error)
	}

	path, ok := h.handlers[pattern]
	if !ok {
		path = make(map[string]func(http.ResponseWriter, *http.Request) error)
		h.handlers[pattern] = path
	}

	path[method] = handler
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.handlers == nil {
		return
	}

	p, ok := h.handlers[r.URL.Path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	method := r.Method

	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		method = "WS"
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, PATCH, OPTIONS, HEAD")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Token")
	w.Header().Set("Access-Control-Expose-Headers", "Access-Control-Allow-Headers, Token")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	m, ok := p[method]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, PATCH, OPTIONS, HEAD")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Token")
	w.Header().Set("Access-Control-Expose-Headers", "Access-Control-Allow-Headers, Token")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if err := m(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
