package simplehttp

import (
	"bufio"
	"embed"
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
	gt "github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"google.golang.org/protobuf/proto"
)

//go:embed all:out
var front embed.FS
var frontDir = "out"

var debug func(*http.ServeMux)

type HttpServerOption struct {
	Mux         *http.ServeMux
	Shunt       *shunt.Shunt
	NodeServer  gn.NodeServer
	Subscribe   gn.SubscribeServer
	Tag         gn.TagServer
	Connections gs.ConnectionsServer
	Config      gc.ConfigServiceServer
	Tools       gt.ToolsServer
}

func (o *HttpServerOption) Routers() Handler {
	return Handler{
		http.MethodGet: {
			"/sublist":  o.GetLinkList,
			"/nodes":    o.Manager,
			"/config":   o.GetConfig,
			"/node/now": o.NodeNow,
		},
		http.MethodPost: {
			"/config":  o.SaveConfig,
			"/sub":     o.SaveLink,
			"/tag":     o.SaveTag,
			"/node":    o.GetNode,
			"/byass":   o.SaveBypass,
			"/latency": o.GetLatency,
		},
		http.MethodDelete: {
			"/conn": o.CloseConn,
			"/node": o.DeleteNode,
			"/sub":  o.DeleteLink,
			"/tag":  o.DeleteTag,
		},
		http.MethodPut: {
			"/node": o.UseNode,
		},
		http.MethodPatch: {
			"/sub":  o.PatchLink,
			"/node": o.SaveNode,
		},
		"WS": {
			"/conn": o.ConnWebsocket,
		},
	}
}

func GetFrontMapping() map[string]bool {
	dirs, err := front.ReadDir(frontDir)
	if err != nil {
		return make(map[string]bool)
	}

	mapp := make(map[string]bool, len(dirs))
	for _, v := range dirs {
		mapp[v.Name()] = true
	}

	mapp["/"] = true

	return mapp
}

func getPathPrefix(str string) string {
	if str == "/" {
		return "/"
	}

	rs := strings.SplitN(str, "/", 3)
	if len(rs) < 2 {
		return ""
	}

	return rs[1]
}

func Httpserver(o HttpServerOption) {
	if debug != nil {
		debug(o.Mux)
	}

	hfs := http.FileServer(http.FS(
		yerror.Ignore(fs.Sub(front, frontDir))))

	frontPrefixMapping := GetFrontMapping()

	handlers := o.Routers()

	o.Mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		log.Debug("http new request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.String()))

		if frontPrefixMapping[getPathPrefix(r.URL.Path)] {
			w.Header().Set("Content-Encoding", "gzip")
			hfs.ServeHTTP(w, r)
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

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, PATCH, OPTIONS, HEAD")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Token")
	w.Header().Set("Access-Control-Expose-Headers", "Access-Control-Allow-Headers, Token")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
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

	err := handler(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else if !w.writed {
		w.WriteHeader(http.StatusOK)
	}
}

func MarshalProtoAndWrite(w http.ResponseWriter, data proto.Message) error {
	bytes, err := proto.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal proto failed: %w", err)
	}

	_, err = w.Write(bytes)
	return err
}

func UnmarshalProtoFromRequest(r *http.Request, data proto.Message) error {
	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}

	return proto.Unmarshal(bytes, data)
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
