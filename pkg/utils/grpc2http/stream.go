package grpc2http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	websocket "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket/x"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

func Stream(srv any, function grpc.StreamHandler) func(http.ResponseWriter, *http.Request) error {
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
