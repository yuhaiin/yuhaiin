package appapi

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
	"path/filepath"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	websocket "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket/x"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	yf "github.com/yuhaiin/yuhaiin.github.io"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

func registerHTTP(srv any, handler grpc.MethodHandler) func(w http.ResponseWriter, r *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		var data []byte
		var err error
		if r.ContentLength > 0 && r.ContentLength <= pool.MaxSegmentSize {
			data = pool.GetBytes(r.ContentLength)
			defer pool.PutBytes(data)
			_, err = io.ReadFull(r.Body, data)
		} else {
			data, err = io.ReadAll(r.Body)
		}
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}

		dec := func(a any) error {
			z, ok := a.(proto.Message)
			if !ok {
				return fmt.Errorf("not proto message")
			}

			return proto.Unmarshal(data, z)
		}

		resp, err := handler(srv, r.Context(), dec, nil)
		if err != nil {
			return fmt.Errorf("handler failed: %w", err)
		}

		res, ok := resp.(proto.Message)
		if !ok {
			return fmt.Errorf("resp not proto message")
		}

		data, err = marshalWithPool(res)
		if err != nil {
			return fmt.Errorf("marshal failed: %w", err)
		}
		defer pool.PutBytes(data)

		w.Header().Set("Content-Type", "application/protobuf")
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("write failed: %w", err)
		}

		return nil
	}
}

func HandleFunc(o *Components, path string, b func(http.ResponseWriter, *http.Request) error) {
	o.Mux.Handle(path, http.HandlerFunc(func(ow http.ResponseWriter, r *http.Request) {
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
				log.Error("handle failed", "path", path, "err", err)
			}
		} else if !w.writed {
			w.WriteHeader(http.StatusOK)
		}
	}))
}

func cross(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
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

func registerWebsocket(srv any, function grpc.StreamHandler) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		return websocket.ServeHTTP(w, r, func(ctx context.Context, c *websocket.Conn) error {
			defer c.Close()

			ctx, cancel := context.WithCancelCause(ctx)
			defer cancel(nil)

			ws := newWebsocketServerServer(ctx)

			go func() {
				for {
					err := c.NextFrameReader(func(h *websocket.Header, frame io.ReadCloser) error {
						if h.ContentLength() > websocket.DefaultMaxPayloadBytes {
							c.Frame = frame
							return errors.New("websocket: frame payload size exceeds limit")
						}

						data := pool.GetBytes(h.ContentLength())
						if _, err := io.ReadFull(frame, data); err != nil {
							return err
						}

						ws.AddRecvData(data)
						return nil
					})
					if err != nil {
						cancel(err)
						return
					}
				}
			}()

			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case data := <-ws.SendData():
						_ = c.SetWriteDeadline(time.Now().Add(time.Second * 5))
						_, err := c.WriteMsg(data, websocket.OpBinary)
						_ = c.SetWriteDeadline(time.Time{})
						pool.PutBytes(data)
						if err != nil {
							cancel(err)
							return
						}
					}

				}
			}()

			err := function(srv, ws)
			cancel(err)
			return err
		})
	}
}

type websocketServer struct {
	ctx      context.Context
	send     chan []byte
	recevied chan []byte
}

func newWebsocketServerServer(ctx context.Context) *websocketServer {
	return &websocketServer{
		ctx:      ctx,
		send:     make(chan []byte, 100),
		recevied: make(chan []byte, 100),
	}
}
func (x *websocketServer) Context() context.Context     { return x.ctx }
func (x *websocketServer) SetHeader(metadata.MD) error  { return nil }
func (x *websocketServer) SendHeader(metadata.MD) error { return nil }
func (x *websocketServer) SetTrailer(metadata.MD)       {}
func (x *websocketServer) SendMsg(m any) error {
	mm, ok := m.(proto.Message)
	if !ok {
		return fmt.Errorf("not proto message")
	}

	data, err := marshalWithPool(mm)
	if err != nil {
		return err
	}

	select {
	case <-x.ctx.Done():
		return x.ctx.Err()
	case x.send <- data:
		return nil
	}
}

func (x *websocketServer) RecvMsg(m any) error {
	mm, ok := m.(proto.Message)
	if !ok {
		return fmt.Errorf("not proto message")
	}

	select {
	case <-x.ctx.Done():
		return x.ctx.Err()
	case msg := <-x.recevied:
		defer pool.PutBytes(msg)
		return proto.Unmarshal(msg, mm)
	}
}

func (x *websocketServer) AddRecvData(data []byte) {
	select {
	case <-x.ctx.Done():
	case x.recevied <- data:
	}
}

func (x *websocketServer) SendData() <-chan []byte { return x.send }

func RegisterHTTP(o *Components) {
	if debug != nil {
		debug(o.Mux)
	}

	HandleFunc(o, "OPTIONS /", func(w http.ResponseWriter, r *http.Request) error { return nil })

	HandleFront(o.Mux)
}

var debug func(*http.ServeMux)

func HandleFront(mux *http.ServeMux) {
	var ffs fs.FS
	edir := os.Getenv("EXTERNAL_WEB")
	if edir != "" {
		ffs = os.DirFS(edir)
	} else {
		ffs = yf.Content
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

		var ctype string

		switch ext {
		case ".html":
			ctype = "text/html"
		case ".js":
			ctype = "text/javascript"
		case ".css":
			ctype = "text/css"
		case ".png":
			ctype = "image/png"
		case ".jpg":
			ctype = "image/jpg"
		case ".jpeg":
			ctype = "image/jpeg"
		case ".svg":
			ctype = "image/svg+xml"
		case ".ico":
			ctype = "image/x-icon"
		case ".gif":
			ctype = "image/gif"
		case ".webp":
			ctype = "image/webp"
		case ".json":
			ctype = "application/json"
		case ".wasm":
			ctype = "application/wasm"
		case ".txt":
			ctype = "text/plain"
		default:
			ctype = "application/octet-stream"
		}

		w.Header().Set("Content-Type", ctype)

		http.ServeFileFS(w, r, ffs, path)
	}))
}

func marshalWithPool(m proto.Message) ([]byte, error) {
	marshal := proto.MarshalOptions{
		UseCachedSize: true,
		Deterministic: true,
	}

	size := marshal.Size(m)

	if size == 0 {
		return []byte{}, nil
	}

	buf := pool.GetBytes(size)

	data, err := marshal.MarshalAppend(buf[:0], m)
	if err != nil {
		pool.PutBytes(buf)
		return nil, err
	}

	return data, nil
}
