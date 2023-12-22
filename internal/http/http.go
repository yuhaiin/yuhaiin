package simplehttp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/components/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	gt "github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

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
			"/sublist": GrpcToHttp(o.Subscribe.Get),
			"/nodes":   GrpcToHttp(o.NodeServer.Manager),
			"/config": func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Core-OS", runtime.GOOS)
				return GrpcToHttp(o.Config.Load)(w, r)
			},
			"/node/now": GrpcToHttp(o.NodeServer.Now),
		},
		http.MethodPost: {
			"/config":  GrpcToHttp(o.Config.Save),
			"/sub":     GrpcToHttp(o.Subscribe.Save),
			"/tag":     GrpcToHttp(o.Tag.Save),
			"/node":    GrpcToHttp(o.NodeServer.Get),
			"/bypass":  GrpcToHttp(o.Tools.SaveRemoteBypassFile),
			"/latency": GrpcToHttp(o.NodeServer.Latency),
		},
		http.MethodDelete: {
			"/conn": GrpcToHttp(o.Connections.CloseConn),
			"/node": GrpcToHttp(o.NodeServer.Remove),
			"/sub":  GrpcToHttp(o.Subscribe.Remove),
			"/tag":  GrpcToHttp(o.Tag.Remove),
		},
		http.MethodPut: {
			"/node": GrpcToHttp(o.NodeServer.Use),
		},
		http.MethodPatch: {
			"/sub":  GrpcToHttp(o.Subscribe.Update),
			"/node": GrpcToHttp(o.NodeServer.Save),
		},
		"WS": {
			"/conn": o.ConnWebsocket,
		},
	}
}

func wrapFS(fs fs.FS, gzip bool) http.Handler {
	hfs := http.FileServer(http.FS(fs))
	if !gzip {
		return hfs
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		hfs.ServeHTTP(w, r)
	})
}

func GetFront() (http.Handler, map[string]bool) {
	var ffs fs.FS
	var gzip bool
	edir := os.Getenv("EXTERNAL_WEB")
	if edir != "" {
		ffs = os.DirFS(edir)
		gzip = false
	} else {
		ffs, _ = fs.Sub(front, frontDir)
		gzip = true
	}

	if ffs == nil {
		return wrapFS(front, false), make(map[string]bool)
	}

	dirs, err := fs.Glob(ffs, "*")
	if err != nil {
		return wrapFS(front, false), make(map[string]bool)
	}

	mapp := make(map[string]bool, len(dirs)+1)
	for _, v := range dirs {
		mapp[v] = true
	}
	mapp["/"] = true

	return wrapFS(ffs, gzip), mapp
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

	hfs, frontPrefixMapping := GetFront()
	handlers := o.Routers()

	o.Mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if frontPrefixMapping[getPathPrefix(r.URL.Path)] {
			hfs.ServeHTTP(w, r)
		} else {
			handlers.ServeHTTP(w, r)
		}

		log.Debug("http new request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.String()),
			slog.String("remoteAddr", r.RemoteAddr),
		)

	}))
}

type ServeHTTP func(http.ResponseWriter, *http.Request) error
type Handler map[string]map[string]ServeHTTP

func (h Handler) Handle(method, pattern string, handler ServeHTTP) {
	path, ok := h[method]
	if !ok {
		path = make(map[string]ServeHTTP)
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
	w.writed = true
	return http.NewResponseController(w.ResponseWriter).Hijack()
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

func getTypeValue[T any]() T {
	var t T
	return t
}

var typeEmpty = reflect.TypeOf(&emptypb.Empty{})

func GrpcToHttp[req, resp proto.Message](function func(context.Context, req) (resp, error)) func(http.ResponseWriter, *http.Request) error {
	reqType := reflect.TypeOf(getTypeValue[req]())
	respType := reflect.TypeOf(getTypeValue[resp]())
	newPr := reflect.New(reqType.Elem()).Interface().(req).ProtoReflect()

	var unmarshalProto func(*http.Request, req) error
	if reqType == typeEmpty {
		unmarshalProto = func(r1 *http.Request, r2 req) error { return nil }
	} else {
		unmarshalProto = func(r1 *http.Request, r2 req) error {
			bytes, err := io.ReadAll(r1.Body)
			if err != nil {
				return err
			}

			return proto.Unmarshal(bytes, r2)
		}
	}

	var marshalProto func(http.ResponseWriter, resp) error

	if respType == typeEmpty {
		marshalProto = func(w http.ResponseWriter, r resp) error { return nil }
	} else {
		marshalProto = func(w http.ResponseWriter, r resp) error {
			bytes, err := proto.Marshal(r)
			if err != nil {
				return fmt.Errorf("marshal proto failed: %w", err)
			}

			_, err = w.Write(bytes)
			return err
		}
	}

	return func(w http.ResponseWriter, r *http.Request) error {
		pr := newPr.New().Interface().(req)

		if err := unmarshalProto(r, pr); err != nil {
			return err
		}

		resp, err := function(r.Context(), pr)
		if err != nil {
			return err
		}

		return marshalProto(w, resp)
	}
}
