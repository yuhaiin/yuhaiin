package simplehttp

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	websocket "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket/x"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (cc *HttpServerOption) ConnWebsocket(w http.ResponseWriter, r *http.Request) error {
	return websocket.ServeHTTP(w, r, func(ctx context.Context, c *websocket.Conn) error {
		defer c.Close()

		var ticker int
		err := websocket.JSON.Receive(c, &ticker)
		if err != nil {
			return err
		}
		if ticker <= 0 {
			ticker = 2000
		}

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		cns := &connectionsNotifyServer{ctx, make(chan *gs.NotifyData, 20)}

		go func() {
			defer cancel()
			err := cc.Connections.Notify(&emptypb.Empty{}, cns)

			if err != nil {
				log.Warn("connections notify failed", "err", err)
			}
		}()

		go func() {
			_, _ = relay.Copy(io.Discard, c)
			cancel()
		}()

		sendFlow := func() error {
			total, err := cc.Connections.Total(ctx, &emptypb.Empty{})
			if err != nil {
				return err
			}
			return websocket.PROTO.Send(c, &gs.NotifyData{Data: &gs.NotifyData_TotalFlow{TotalFlow: total}})
		}

		if err = sendFlow(); err != nil {
			return err
		}

		for {
			select {
			case <-ctx.Done():
				return nil

			case m := <-cns.msgChan:
				if err = websocket.PROTO.Send(c, m); err != nil {
					return err
				}

			case <-time.After(time.Duration(ticker) * time.Millisecond):
				if err = sendFlow(); err != nil {
					return err
				}
			}
		}
	})
}

type connectionsNotifyServer struct {
	ctx     context.Context
	msgChan chan *gs.NotifyData
}

func (x *connectionsNotifyServer) Send(m *gs.NotifyData) error {
	select {
	case <-x.ctx.Done():
		return x.ctx.Err()
	case x.msgChan <- m:
	}

	return nil
}

func (x *connectionsNotifyServer) Context() context.Context     { return x.ctx }
func (x *connectionsNotifyServer) SetHeader(metadata.MD) error  { return nil }
func (x *connectionsNotifyServer) SendHeader(metadata.MD) error { return nil }
func (x *connectionsNotifyServer) SetTrailer(metadata.MD)       {}
func (x *connectionsNotifyServer) SendMsg(m any) error          { return nil }
func (x *connectionsNotifyServer) RecvMsg(m any) error          { return nil }
