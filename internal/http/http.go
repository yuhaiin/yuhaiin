package simplehttp

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/components/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

//go:embed build
var front embed.FS

var debug func(*http.ServeMux)

type HttpServerOption struct {
	Mux         *http.ServeMux
	Shunt       *shunt.Shunt
	NodeServer  gn.NodeServer
	Subscribe   gn.SubscribeServer
	Tag         gn.TagServer
	Connections gs.ConnectionsServer
	Config      gc.ConfigServiceServer
}

func (o *HttpServerOption) Routers() Handler {
	return Handler{
		"GET": {
			"/grouplist":   o.GroupList,
			"/group":       o.GetGroups,
			"/sublist":     o.GetLinkList,
			"/taglist":     o.TagList,
			"/config/json": o.GetConfig,
			"/node/now":    o.NodeNow,
			"/node":        o.GetNode,
			"/latency":     o.GetLatency,
		},
		"POST": {
			"/config": o.SaveConfig,
			"/node":   o.SaveNode,
			"/sub":    o.SaveLink,
			"/tag":    o.SaveTag,
		},
		"DELETE": {
			"/conn": o.CloseConn,
			"/node": o.DeleteNOde,
			"/sub":  o.DeleteLink,
			"/tag":  o.DeleteTag,
		},
		"PUT": {
			"/node": o.AddNode,
		},
		"PATCH": {
			"/sub": o.PatchLink,
		},
		"WS": {
			"/conn": o.ConnWebsocket,
		},
	}
}

func Httpserver(o HttpServerOption) {
	if debug != nil {
		debug(o.Mux)
	}

	fs := http.FileServer(http.FS(yerror.Ignore(fs.Sub(front, "build"))))

	handlers := o.Routers()

	o.Mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}

type Handler map[string]map[string]func(http.ResponseWriter, *http.Request) error

func (h Handler) Handle(method, pattern string, handler func(http.ResponseWriter, *http.Request) error) {
	path, ok := h[method]
	if !ok {
		path = make(map[string]func(http.ResponseWriter, *http.Request) error)
		h[method] = path
	}

	path[pattern] = handler
}

type wrapResponseWriter struct {
	http.ResponseWriter
	writed bool
}

func (w *wrapResponseWriter) Write(b []byte) (int, error) {
	if !w.writed {
		w.writed = true
	}

	return w.ResponseWriter.Write(b)
}

func (w *wrapResponseWriter) WriteHeader(s int) {
	if !w.writed {
		w.writed = true
	}

	w.ResponseWriter.WriteHeader(s)
}

func (w *wrapResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}

	w.writed = true

	return h.Hijack()
}

func (h Handler) ServeHTTP(ow http.ResponseWriter, r *http.Request) {

	w := &wrapResponseWriter{ow, false}

	method := r.Method

	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		method = "WS"
	}

	methods, ok := h[method]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	handler, ok := methods[r.URL.Path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
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

	err := handler(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else if !w.writed {
		w.WriteHeader(http.StatusOK)
	}
}

func MarshalProtoAndWrite(w http.ResponseWriter, data proto.Message, opts ...func(*protojson.MarshalOptions)) error {
	marshaler := protojson.MarshalOptions{}

	for _, f := range opts {
		f(&marshaler)
	}

	bytes, err := marshaler.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal proto failed: %w", err)
	}

	_, err = w.Write(bytes)
	return err
}

func MarshalJsonAndWrite(w http.ResponseWriter, data interface{}) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, err = w.Write(bytes)
	return err
}

func UnmarshalProtoFromRequest(r *http.Request, data proto.Message, opts ...func(*protojson.UnmarshalOptions)) error {
	unmarshaler := protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}

	for _, f := range opts {
		f(&unmarshaler)
	}

	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}

	return unmarshaler.Unmarshal(bytes, data)
}

func UnmarshalJsonFromRequest(r *http.Request, data interface{}) error {
	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes, data)
}

type wne[T any] struct {
	t   T
	err error
}

func WhenNoError[T any](t T, err error) *wne[T] { return &wne[T]{t, err} }

func (w *wne[T]) Do(f func(T) error) error {
	if w.err != nil {
		return w.err
	}

	return f(w.t)
}
