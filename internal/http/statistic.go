package simplehttp

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	tps "github.com/Asutorufa/yuhaiin/internal/http/templates"
	websocket "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket/x"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

type conn struct {
	emptyHTTP
	stt gs.ConnectionsServer
}

func (c *conn) Delete(w http.ResponseWriter, r *http.Request) error {
	id := r.URL.Query().Get("id")

	i, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}

	_, err = c.stt.CloseConn(context.TODO(), &gs.ConnectionsId{Ids: []uint64{i}})
	if err != nil {
		return err
	}

	w.Write([]byte("OK"))
	return nil
}

func (c *conn) Get(w http.ResponseWriter, r *http.Request) error {
	return TPS.BodyExecute(w, nil, tps.STATISTIC)
}

func (cc *conn) Websocket(w http.ResponseWriter, r *http.Request) error {
	return websocket.ServeHTTP(w, r, cc.handler)
}

func (cc *conn) handler(c *websocket.Conn) error {
	defer c.Close()

	var tickerStr string
	err := websocket.Message.Receive(c, &tickerStr)
	if err != nil {
		return err
	}

	t, err := strconv.ParseInt(tickerStr, 10, 0)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	go cc.stt.Notify(&emptypb.Empty{}, &connectionsNotifyServer{ctx, c})

	ticker := time.NewTicker(time.Duration(t) * time.Millisecond)
	defer ticker.Stop()

	go func() {
		io.Copy(io.Discard, c)
		cancel()
	}()

	if err = cc.sendFlow(c); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker.C:
			if err = cc.sendFlow(c); err != nil {
				return err
			}
		}
	}
}

func (cc *conn) sendFlow(wsConn *websocket.Conn) error {
	total, err := cc.stt.Total(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	return websocket.JSON.Send(wsConn, map[string]any{"type": 0, "flow": total})
}

type connectionsNotifyServer struct {
	ctx    context.Context
	wsConn *websocket.Conn
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
		return map[string]any{"type": 1, "data": cs}
	}

	if m.GetNotifyRemoveConnections() != nil && m.GetNotifyRemoveConnections().Ids != nil {
		return map[string]any{"type": 2, "data": m.GetNotifyRemoveConnections().Ids}
	}
	return nil
}
func (x *connectionsNotifyServer) Context() context.Context     { return x.ctx }
func (x *connectionsNotifyServer) SetHeader(metadata.MD) error  { return nil }
func (x *connectionsNotifyServer) SendHeader(metadata.MD) error { return nil }
func (x *connectionsNotifyServer) SetTrailer(metadata.MD)       {}
func (x *connectionsNotifyServer) SendMsg(m interface{}) error  { return nil }
func (x *connectionsNotifyServer) RecvMsg(m interface{}) error  { return nil }
