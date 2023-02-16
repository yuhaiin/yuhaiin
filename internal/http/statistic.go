package simplehttp

import (
	"context"
	"net/http"
	"strconv"

	tps "github.com/Asutorufa/yuhaiin/internal/http/templates"
	websocket "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket/x"
	grpcsts "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type conn struct {
	emptyHTTP
	stt grpcsts.ConnectionsServer
}

func (c *conn) Delete(w http.ResponseWriter, r *http.Request) error {
	id := r.URL.Query().Get("id")

	i, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return err
	}

	_, err = c.stt.CloseConn(context.TODO(), &grpcsts.ConnectionsId{Ids: []uint64{i}})
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

	for {
		var tmp string
		err := websocket.Message.Receive(c, &tmp)
		if err != nil {
			return err
		}
		total, err := cc.stt.Total(context.TODO(), &emptypb.Empty{})
		if err != nil {
			return err
		}
		conns, err := cc.stt.Conns(context.TODO(), &emptypb.Empty{})
		if err != nil {
			return err
		}
		err = websocket.JSON.Send(c, map[string]any{"flow": total, "connections": conns.Connections})
		if err != nil {
			return err
		}
	}
}
