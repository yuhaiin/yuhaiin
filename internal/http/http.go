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

	"github.com/Asutorufa/yuhaiin/internal/appapi"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func Server(o *appapi.Components) {
	if debug != nil {
		debug(o.Mux)
	}

	HandleFront(o.Mux)
	ServeHTTP(o)
}

var debug func(*http.ServeMux)

func ServeHTTP(o *appapi.Components) {
	for k, b := range map[string]func(http.ResponseWriter, *http.Request) error{
		"GET /sublist":    GrpcToHttp(o.Subscribe.Get),
		"GET /nodes":      GrpcToHttp(o.Node.Manager),
		"GET /config":     GrpcToHttp(o.Setting.Load),
		"GET /info":       GrpcToHttp(o.Setting.Info),
		"GET /interfaces": GrpcToHttp(o.Tools.GetInterface),
		"GET /node/now":   GrpcToHttp(o.Node.Now),

		"POST /config":  GrpcToHttp(o.Setting.Save),
		"POST /sub":     GrpcToHttp(o.Subscribe.Save),
		"POST /tag":     GrpcToHttp(o.Tag.Save),
		"POST /node":    GrpcToHttp(o.Node.Get),
		"POST /bypass":  GrpcToHttp(o.Tools.SaveRemoteBypassFile),
		"POST /latency": GrpcToHttp(o.Node.Latency),

		"DELETE /conn": GrpcToHttp(o.Connections.CloseConn),
		"DELETE /node": GrpcToHttp(o.Node.Remove),
		"DELETE /sub":  GrpcToHttp(o.Subscribe.Remove),
		"DELETE /tag":  GrpcToHttp(o.Tag.Remove),

		"PUT /node": GrpcToHttp(o.Node.Use),

		"PATCH /sub":  GrpcToHttp(o.Subscribe.Update),
		"PATCH /node": GrpcToHttp(o.Node.Save),

		// WEBSOCKET
		"GET /conn": ConnWebsocket(o),
	} {
		o.Mux.Handle(k, http.HandlerFunc(func(ow http.ResponseWriter, r *http.Request) {
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
