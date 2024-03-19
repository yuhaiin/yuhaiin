package simplehttp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime"

	"github.com/Asutorufa/yuhaiin/pkg/components/shunt"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	gt "github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

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

func (o *HttpServerOption) ServeHTTP(mux *http.ServeMux) {
	for k, b := range map[string]func(http.ResponseWriter, *http.Request) error{
		"GET /sublist": GrpcToHttp(o.Subscribe.Get),
		"GET /nodes":   GrpcToHttp(o.NodeServer.Manager),
		"GET /config": func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Core-OS", runtime.GOOS)
			return GrpcToHttp(o.Config.Load)(w, r)
		},
		"GET /interfaces": GrpcToHttp(o.Tools.GetInterface),
		"GET /node/now":   GrpcToHttp(o.NodeServer.Now),

		"POST /config":  GrpcToHttp(o.Config.Save),
		"POST /sub":     GrpcToHttp(o.Subscribe.Save),
		"POST /tag":     GrpcToHttp(o.Tag.Save),
		"POST /node":    GrpcToHttp(o.NodeServer.Get),
		"POST /bypass":  GrpcToHttp(o.Tools.SaveRemoteBypassFile),
		"POST /latency": GrpcToHttp(o.NodeServer.Latency),

		"DELETE /conn": GrpcToHttp(o.Connections.CloseConn),
		"DELETE /node": GrpcToHttp(o.NodeServer.Remove),
		"DELETE /sub":  GrpcToHttp(o.Subscribe.Remove),
		"DELETE /tag":  GrpcToHttp(o.Tag.Remove),

		"PUT /node": GrpcToHttp(o.NodeServer.Use),

		"PATCH /sub":  GrpcToHttp(o.Subscribe.Update),
		"PATCH /node": GrpcToHttp(o.NodeServer.Save),

		// WEBSOCKET
		"GET /conn": o.ConnWebsocket,
	} {
		mux.Handle(k, http.HandlerFunc(func(ow http.ResponseWriter, r *http.Request) {
			cross(ow)
			w := &wrapResponseWriter{ow, false}
			err := b(w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			} else if !w.writed {
				w.WriteHeader(http.StatusOK)
			}
		}))

	}
}

func cross(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, PATCH, OPTIONS, HEAD")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Token")
	w.Header().Set("Access-Control-Expose-Headers", "Access-Control-Allow-Headers, Token")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func HandleFront(mux *http.ServeMux) {
	var ffs fs.FS
	edir := os.Getenv("EXTERNAL_WEB")
	if edir != "" {
		ffs = os.DirFS(edir)
	} else {
		ffs, _ = fs.Sub(front, "out")
	}

	if ffs == nil {
		return
	}

	dirs, err := fs.Glob(ffs, "*")
	if err != nil {
		return
	}

	gzip := edir == ""

	handler := http.FileServer(http.FS(ffs))
	if gzip {
		hfs := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			hfs.ServeHTTP(w, r)
		})
	}

	mux.Handle("GET /", handler)
	for _, v := range dirs {
		mux.Handle(fmt.Sprintf("GET %s/", v), handler)
	}
}

func Httpserver(o HttpServerOption) {
	if debug != nil {
		debug(o.Mux)
	}

	HandleFront(o.Mux)
	o.ServeHTTP(o.Mux)
}

type wrapResponseWriter struct {
	http.ResponseWriter
	writed bool
}

func (w *wrapResponseWriter) Write(b []byte) (int, error) {
	w.writed = true
	return w.ResponseWriter.Write(b)
}

func (w *wrapResponseWriter) WriteHeader(s int) {
	w.writed = true
	w.ResponseWriter.WriteHeader(s)
}

func (w *wrapResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.writed = true
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func GrpcToHttp[req, resp proto.Message](function func(context.Context, req) (resp, error)) func(http.ResponseWriter, *http.Request) error {
	typeEmpty := reflect.TypeOf(&emptypb.Empty{})
	reqType := reflect.TypeOf(*new(req))
	respType := reflect.TypeOf(*new(resp))
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
