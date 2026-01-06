package app

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/chore"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pt "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/grpc2http"
	yf "github.com/yuhaiin/yuhaiin.github.io"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AppInstance struct {
	Node        api.NodeServer
	Tools       api.ToolsServer
	Subscribe   api.SubscribeServer
	Connections api.ConnectionsServer
	Inbound     api.InboundServer
	Resolver    api.ResolverServer
	Lists       api.ListsServer
	Rules       api.RulesServer
	Tag         api.TagServer
	Backup      api.BackupServer
	// TODO deprecate configService, new service chore
	Setting api.ConfigServiceServer
	Mux     *http.ServeMux
	*StartOptions
	closers *closers
}

type closers struct {
	closers []*moduleCloser
}

func (a *closers) AddCloser(name string, z io.Closer) {
	a.closers = append(a.closers, &moduleCloser{z, name})
}

func (a *closers) Close() error {
	closers := slices.Clone(a.closers)
	slices.Reverse(closers)

	var err error
	for _, v := range closers {
		if er := v.Close(); er != nil {
			err = errors.Join(err, fmt.Errorf("%s close error: %w", v.name, er))
		}
	}

	return err
}

type moduleCloser struct {
	io.Closer
	name string
}

func (m *moduleCloser) Close() error {
	log.Info("close", "module", m.name)
	defer log.Info("closed", "module", m.name)
	return m.Closer.Close()
}

func (app *AppInstance) RegisterServer() {
	grpcServer := &grpcRegister{
		s:    app.GRPCServer,
		mux:  app.Mux,
		auth: app.Auth,
	}

	api.RegisterConfigServiceServer(grpcServer, app.Setting)
	api.RegisterInboundServer(grpcServer, app.Inbound)
	api.RegisterResolverServer(grpcServer, app.Resolver)
	api.RegisterListsServer(grpcServer, app.Lists)
	api.RegisterRulesServer(grpcServer, app.Rules)

	api.RegisterNodeServer(grpcServer, app.Node)
	api.RegisterSubscribeServer(grpcServer, app.Subscribe)
	api.RegisterTagServer(grpcServer, app.Tag)

	api.RegisterConnectionsServer(grpcServer, app.Connections)

	api.RegisterToolsServer(grpcServer, app.Tools)

	api.RegisterBackupServer(grpcServer, app.Backup)

	RegisterHTTP(app.Mux)
}

type grpcRegister struct {
	mux  *http.ServeMux
	s    *grpc.Server
	auth *Auth
}

func (g *grpcRegister) RegisterService(desc *grpc.ServiceDesc, impl any) {
	if g.s != nil { // when android, g.s is nil
		log.Info("register grpc service", "name", desc.ServiceName)
		g.s.RegisterService(desc, impl)
	}

	for _, method := range desc.Methods {
		path := fmt.Sprintf("POST /%s/%s", desc.ServiceName, method.MethodName)
		log.Info("register http handler", "path", path)
		HandleFunc(g.mux, g.auth, path, grpc2http.Call(impl, method.Handler))
	}

	for _, method := range desc.Streams {
		path := fmt.Sprintf("GET /%s/%s", desc.ServiceName, method.StreamName)
		log.Info("register websocket handler", "path", path)
		HandleFunc(g.mux, g.auth, path, grpc2http.Stream(impl, method.Handler))
	}
}

func (a *AppInstance) Close() error {
	sysproxy.Unset()
	return a.closers.Close()
}

type StartOptions struct {
	BypassConfig   chore.DB
	ResolverConfig chore.DB
	InboundConfig  chore.DB
	ChoreConfig    chore.DB
	BackupConfig   chore.DB

	ProcessDumper netapi.ProcessDumper

	Auth       *Auth
	GRPCServer *grpc.Server

	ConfigPath string
}

type Auth struct {
	Username [32]byte
	Password [32]byte
}

func NewAuth(username, password string) *Auth {
	return &Auth{
		Username: sha256.Sum256([]byte(username)),
		Password: sha256.Sum256([]byte(password)),
	}
}

func (a *Auth) Auth(password, username string) bool {
	rSumUser := sha256.Sum256([]byte(username))
	rSumPass := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(rSumUser[:], a.Username[:]) == 1 && subtle.ConstantTimeCompare(rSumPass[:], a.Password[:]) == 1
}

func (a *Auth) GrpcAuth() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "metadata not found")
		}

		as := md.Get("Authorization")
		if len(as) == 0 {
			return nil, status.Error(codes.Unauthenticated, "authorization header not found")
		}

		ru, rp, ok := pt.ParseBasicAuth(as[0])
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "authorization failed")
		}

		if !a.Auth(ru, rp) {
			return nil, status.Error(codes.Unauthenticated, "authorization failed")
		}

		return handler(ctx, req)
	}
}

func HandleFunc(mux *http.ServeMux, auth *Auth, path string, b func(http.ResponseWriter, *http.Request) error) {
	mux.Handle(path, http.HandlerFunc(func(ow http.ResponseWriter, r *http.Request) {
		if auth != nil {
			username, password, ok := r.BasicAuth()
			if !ok || !auth.Auth(password, username) {
				ow.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
				http.Error(ow, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		cross(r, ow)

		w := &wrapResponseWriter{ow, false}
		err := b(w, r)
		if err != nil {
			if !w.writed {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}

			if !errors.Is(err, context.DeadlineExceeded) &&
				!errors.Is(err, os.ErrDeadlineExceeded) &&
				!errors.Is(err, context.Canceled) {
				log.Error("handle failed", "path", path, "err", err)
			}
		} else if !w.writed {
			w.WriteHeader(http.StatusOK)
		}
	}))
}

func cross(r *http.Request, w http.ResponseWriter) {
	// origin := r.Header.Get("Origin")

	// if os.Getenv("DEBUG_YUHAIIN") != "true" {
	// 	if origin == "" {
	// 		return
	// 	}

	// 	if origin != "https://yuhaiin.github.io" &&
	// 		!strings.HasPrefix(origin, "http://127.0.0.1") &&
	// 		!strings.HasPrefix(origin, "http://localhost") {
	// 		return
	// 	}
	// } else {
	// 	origin = "*"
	// }

	origin := "*"

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, PATCH, OPTIONS, HEAD")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Token")
	w.Header().Set("Access-Control-Expose-Headers", "Access-Control-Allow-Headers, Token")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
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

func RegisterHTTP(mux *http.ServeMux) {
	if disabledPprof, _ := strconv.ParseBool("DISABLED_PPROF"); !disabledPprof {
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	}

	HandleFunc(mux, nil, "OPTIONS /", func(w http.ResponseWriter, r *http.Request) error { return nil })

	handleFront(mux)
}

func handleFront(mux *http.ServeMux) {
	var ffs fs.FS
	edir := os.Getenv("EXTERNAL_WEB")
	if edir != "" {
		ffs = os.DirFS(edir)
	} else {
		ffs = yf.Content
	}

	cTypeMap := map[string]string{
		".html": "text/html",
		".js":   "text/javascript",
		".css":  "text/css",
		".png":  "image/png",
		".jpg":  "image/jpg",
		".jpeg": "image/jpeg",
		".svg":  "image/svg+xml",
		".ico":  "image/x-icon",
		".gif":  "image/gif",
		".webp": "image/webp",
		".json": "application/json",
		".txt":  "text/plain",
		".mp4":  "video/mp4",
		".mp3":  "audio/mpeg",
		".wav":  "audio/wav",
		".ogg":  "audio/ogg",
		".wasm": "application/wasm",
	}

	mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		f, err := ffs.Open(path)
		if err != nil {
			path = filepath.Join(path, "index.html")
			f, err = ffs.Open(path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
		}
		_ = f.Close()

		ext := filepath.Ext(path)

		var ctype string = "application/octet-stream"

		if t, ok := cTypeMap[ext]; ok {
			ctype = t
		}

		w.Header().Set("Content-Type", ctype)

		http.ServeFileFS(w, r, ffs, path)
	}))
}
