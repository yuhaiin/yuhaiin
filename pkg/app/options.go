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
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/chore"
	"github.com/Asutorufa/yuhaiin/pkg/control"
	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	pyroscopepprof "github.com/grafana/pyroscope-go/godeltaprof/http/pprof"
	yf "github.com/yuhaiin/yuhaiin.github.io"
)

type AppInstance struct {
	Node        control.NodePort
	Tools       control.ToolsPort
	Subscribe   control.SubscribePort
	Connections control.ConnectionsPort
	Inbound     control.InboundPort
	Resolver    control.ResolverPort
	Lists       control.ListsPort
	Rules       control.RulesPort
	Tag         control.TagPort
	Backup      control.BackupPort
	// TODO deprecate configService, new service chore
	Setting control.ConfigPort
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
	registerV1HTTP(app)
	RegisterHTTP(app.Mux)
}

func registerV1HTTP(app *AppInstance) {
	httpapi.RegisterV1(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		HandleFunc(app.Mux, app.Auth, pattern, handler)
	}, httpapi.Services{
		Config:      app.Setting,
		Lists:       app.Lists,
		Rules:       app.Rules,
		Inbound:     app.Inbound,
		Resolver:    app.Resolver,
		Node:        app.Node,
		Subscribe:   app.Subscribe,
		Tag:         app.Tag,
		Connections: app.Connections,
		Tools:       app.Tools,
		Backup:      app.Backup,
	})
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

	Auth *Auth

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

func HandleFunc(mux *http.ServeMux, auth *Auth, path string, b func(http.ResponseWriter, *http.Request) error) {
	mux.Handle(path, http.HandlerFunc(func(ow http.ResponseWriter, r *http.Request) {
		w := &wrapResponseWriter{ow, false}

		cross(r, w)

		if auth != nil {
			token := r.URL.Query().Get("token")
			if token != "" {
				r.Header.Set("Authorization", "Basic "+token)
			}

			username, password, ok := r.BasicAuth()
			if !ok || !auth.Auth(password, username) {
				// ow.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

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
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Token, Authorization")
	w.Header().Set("Access-Control-Expose-Headers", "Access-Control-Allow-Headers, Token, Authorization")
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

func (w *wrapResponseWriter) Flush() {
	w.writed = true
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *wrapResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.writed = true
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func RegisterHTTP(mux *http.ServeMux) {
	if disabledPprof, _ := strconv.ParseBool("DISABLED_PPROF"); !disabledPprof {
		runtime.SetCPUProfileRate(25)
		runtime.SetBlockProfileRate(1000)
		runtime.SetMutexProfileFraction(20)
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)

		mux.HandleFunc("GET /debug/pprof/delta_heap", pyroscopepprof.Heap)
		mux.HandleFunc("GET /debug/pprof/delta_block", pyroscopepprof.Block)
		mux.HandleFunc("GET /debug/pprof/delta_mutex", pyroscopepprof.Mutex)

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
