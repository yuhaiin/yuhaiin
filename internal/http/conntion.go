package simplehttp

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	websocket "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket/x"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (c *HttpServerOption) CloseConn(w http.ResponseWriter, r *http.Request) error {
	i, err := strconv.ParseUint(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		return err
	}

	_, err = c.Connections.CloseConn(r.Context(), &gs.ConnectionsId{Ids: []uint64{i}})
	return err
}

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

		go func() {
			defer cancel()
			err := cc.Connections.Notify(&emptypb.Empty{},
				&connectionsNotifyServer{ctx, c})
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
			return websocket.JSON.Send(c, &connectPacket{0, nil, nil, total})
		}

		if err = sendFlow(); err != nil {
			return err
		}

		for {
			select {
			case <-ctx.Done():
				return nil

			case <-time.After(time.Duration(ticker) * time.Millisecond):
				if err = sendFlow(); err != nil {
					return err
				}
			}
		}
	})
}

type connectionsNotifyServer struct {
	ctx    context.Context
	wsConn *websocket.Conn
}

type connectPacket struct {
	Type        int                     `json:"type"`
	RemoveIDs   []uint64                `json:"remove_ids,omitempty"`
	Connections []*statistic.Connection `json:"connections,omitempty"`
	Flow        *gs.TotalFlow           `json:"flow,omitempty"`
}

func (x *connectionsNotifyServer) Send(m *gs.NotifyData) error {
	if mm := x.getData(m); mm != nil {
		return websocket.JSON.Send(x.wsConn, mm)
	}

	return nil
}

func (x *connectionsNotifyServer) getData(m *gs.NotifyData) any {
	if m.GetNotifyNewConnections() != nil && m.GetNotifyNewConnections().Connections != nil {
		cs := m.GetNotifyNewConnections().Connections
		if len(cs) > 1 {
			sort.Slice(cs, func(i, j int) bool { return cs[i].Id <= cs[j].Id })
		}
		return &connectPacket{1, nil, cs, nil}
	}

	if m.GetNotifyRemoveConnections() != nil && m.GetNotifyRemoveConnections().Ids != nil {
		return &connectPacket{2, m.GetNotifyRemoveConnections().Ids, nil, nil}
	}
	return nil
}
func (x *connectionsNotifyServer) Context() context.Context     { return x.ctx }
func (x *connectionsNotifyServer) SetHeader(metadata.MD) error  { return nil }
func (x *connectionsNotifyServer) SendHeader(metadata.MD) error { return nil }
func (x *connectionsNotifyServer) SetTrailer(metadata.MD)       {}
func (x *connectionsNotifyServer) SendMsg(m interface{}) error  { return nil }
func (x *connectionsNotifyServer) RecvMsg(m interface{}) error  { return nil }
