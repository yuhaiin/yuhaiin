package simplehttp

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/components/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"golang.org/x/exp/slog"
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

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	if err := handler(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
