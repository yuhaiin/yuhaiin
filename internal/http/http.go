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
	config "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	snode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	sstatistic "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"golang.org/x/exp/slog"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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

	handlersImpl := &HandlerImpl{
		cf:  o.Config,
		nm:  o.NodeServer,
		ts:  o.Tag,
		st:  o.Shunt,
		sb:  o.Subscribe,
		stt: o.Connections,
	}

	var routes = map[string]map[string]func(http.ResponseWriter, *http.Request) error{
		"GET": {
			"/grouplist":   handlersImpl.GroupList,
			"/group":       handlersImpl.Groups,
			"/sublist":     handlersImpl.GetLinkList,
			"/taglist":     handlersImpl.TagList,
			"/config/json": handlersImpl.Config,
			"/node/now":    handlersImpl.NodeNow,
			"/node":        handlersImpl.GetNode,
			"/latency":     handlersImpl.Get,
		},
		"POST": {
			"/config": handlersImpl.Post,
			"/node":   handlersImpl.SaveNode,
			"/sub":    handlersImpl.SaveLink,
			"/tag":    handlersImpl.SaveTag,
		},
		"DELETE": {
			"/conn": handlersImpl.CloseConn,
			"/node": handlersImpl.DeleteNOde,
			"/sub":  handlersImpl.DeleteLink,
			"/tag":  handlersImpl.DeleteTag,
		},
		"PUT": {
			"/node": handlersImpl.AddNode,
		},
		"PATCH": {
			"/sub": handlersImpl.PatchLink,
		},
		"WS": {
			"/conn": handlersImpl.ConnWebsocket,
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
