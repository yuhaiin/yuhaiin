package simplehttp

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	websocket "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket/x"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func GrpcServerStreamingToWebsocket[req ProtoMsg[T], T any, T2 any](function func(req, grpc.ServerStreamingServer[T2]) error) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		return websocket.ServeHTTP(w, r, func(ctx context.Context, c *websocket.Conn) error {
			defer c.Close()

			ctx, cancel := context.WithCancelCause(ctx)
			defer cancel(nil)

			req := req(new(T))
			err := websocket.PROTO.Receive(c, req)
			if err != nil {
				return err
			}

			ws := newWebsocketServerServer[T2](ctx)

			go func() {
				err := function(req, ws)
				cancel(err)
			}()

			go func() {
				_, err := relay.Copy(io.Discard, c)
				cancel(err)
			}()

			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-ws.triggerChan():
					m := ws.popMsgs()
					for _, msg := range m {
						_ = c.SetWriteDeadline(time.Now().Add(time.Second * 5))
						err := websocket.PROTO.Send(c, msg)
						_ = c.SetWriteDeadline(time.Time{})
						if err != nil {
							return err
						}
					}
				}
			}
		})
	}
}

type websocketServer[T any] struct {
	ctx     context.Context
	msgs    []*T
	trigger chan struct{}
	mu      sync.Mutex
}

func newWebsocketServerServer[T any](ctx context.Context) *websocketServer[T] {
	return &websocketServer[T]{
		ctx:     ctx,
		trigger: make(chan struct{}, 1),
	}
}

func (x *websocketServer[T]) popMsgs() []*T {
	x.mu.Lock()
	msg := x.msgs
	x.msgs = nil
	x.mu.Unlock()

	return msg
}

func (x *websocketServer[T]) Send(m *T) error {
	select {
	case <-x.ctx.Done():
		return x.ctx.Err()
	default:
		x.mu.Lock()
		x.msgs = append(x.msgs, m)
		x.mu.Unlock()

		select {
		case x.trigger <- struct{}{}:
		default:
		}
	}

	return nil
}

func (x *websocketServer[T]) triggerChan() <-chan struct{} { return x.trigger }
func (x *websocketServer[T]) Context() context.Context     { return x.ctx }
func (x *websocketServer[T]) SetHeader(metadata.MD) error  { return nil }
func (x *websocketServer[T]) SendHeader(metadata.MD) error { return nil }
func (x *websocketServer[T]) SetTrailer(metadata.MD)       {}
func (x *websocketServer[T]) SendMsg(m any) error          { return nil }
func (x *websocketServer[T]) RecvMsg(m any) error          { return nil }
