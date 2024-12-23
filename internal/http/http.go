package simplehttp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"

	"github.com/Asutorufa/yuhaiin/internal/appapi"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	yf "github.com/yuhaiin/yuhaiin.github.io"
	"google.golang.org/protobuf/proto"
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
		"GET /info":       GrpcToHttp(o.Setting.Info),
		"GET /interfaces": GrpcToHttp(o.Tools.GetInterface),
		"GET /node/now":   GrpcToHttp(o.Node.Now),

		"GET /sublist": GrpcToHttp(o.Subscribe.Get),
		"PATCH /sub":   GrpcToHttp(o.Subscribe.Update),
		"POST /sub":    GrpcToHttp(o.Subscribe.Save),
		"DELETE /sub":  GrpcToHttp(o.Subscribe.Remove),

		"GET /config":  GrpcToHttp(o.Setting.Load),
		"POST /config": GrpcToHttp(o.Setting.Save),

		"GET /tags":   GrpcToHttp(o.Tag.List),
		"DELETE /tag": GrpcToHttp(o.Tag.Remove),
		"POST /tag":   GrpcToHttp(o.Tag.Save),

		"GET /nodes":    GrpcToHttp(o.Node.List),
		"POST /node":    GrpcToHttp(o.Node.Get),
		"PATCH /node":   GrpcToHttp(o.Node.Save),
		"DELETE /node":  GrpcToHttp(o.Node.Remove),
		"PUT /node":     GrpcToHttp(o.Node.Use),
		"POST /latency": GrpcToHttp(o.Node.Latency),

		"GET /inbounds":   GrpcToHttp(o.Inbound.List),
		"POST /inbound":   GrpcToHttp(o.Inbound.Get),
		"PATCH /inbound":  GrpcToHttp(o.Inbound.Save),
		"DELETE /inbound": GrpcToHttp(o.Inbound.Remove),

		"GET /bypass":               GrpcToHttp(o.Rc.Load),
		"PATCH /bypass":             GrpcToHttp(o.Rc.Save),
		"POST /bypass/reload":       GrpcToHttp(o.Rc.Reload),
		"POST /bypass/test":         GrpcToHttp(o.Rc.Test),
		"GET /bypass/block_history": GrpcToHttp(o.Rc.BlockHistory),

		"DELETE /conn":             GrpcToHttp(o.Connections.CloseConn),
		"GET /conn/failed_history": GrpcToHttp(o.Connections.FailedHistory),
		"GET /conn/history":        GrpcToHttp(o.Connections.AllHistory),

		"GET /resolvers":   GrpcToHttp(o.Resolver.List),
		"POST /resolver":   GrpcToHttp(o.Resolver.Get),
		"PATCH /resolver":  GrpcToHttp(o.Resolver.Save),
		"DELETE /resolver": GrpcToHttp(o.Resolver.Remove),

		"GET /flow/total": GrpcToHttp(o.Connections.Total),
		// WEBSOCKET
		"GET /conn": GrpcServerStreamingToWebsocket(o.Connections.Notify),

		"OPTIONS /": func(w http.ResponseWriter, r *http.Request) error { return nil },
	} {
		o.Mux.Handle(k, http.HandlerFunc(func(ow http.ResponseWriter, r *http.Request) {
			cross(ow)
			w := &wrapResponseWriter{ow, false}
			err := b(w, r)
			if err != nil {
				if !w.writed {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}

				if !errors.Is(err, context.DeadlineExceeded) &&
					!errors.Is(err, os.ErrDeadlineExceeded) &&
					!errors.Is(err, context.Canceled) {
					log.Error("handle failed", "path", k, "err", err)
				}
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
		ffs = yf.Content
	}

	dirs, err := fs.Glob(ffs, "*")
	if err != nil {
		return
	}

	handler := http.FileServer(http.FS(ffs))

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

type ProtoMsg[T any] interface {
	proto.Message
	*T
}

func GrpcToHttp[req ProtoMsg[T], resp ProtoMsg[T2], T, T2 any](function func(context.Context, req) (resp, error)) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		req := req(new(T))

		if r.Method != http.MethodGet {
			reqBytes, err := io.ReadAll(r.Body)
			if err != nil {
				return err
			}

			err = proto.Unmarshal(reqBytes, req)
			if err != nil {
				return err
			}
		}

		resp, err := function(r.Context(), req)
		if err != nil {
			return err
		}

		respBytes, err := proto.Marshal(resp)
		if err != nil {
			return err
		}

		_, err = w.Write(respBytes)
		return err
	}
}
