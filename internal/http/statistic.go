package simplehttp

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"

	tps "github.com/Asutorufa/yuhaiin/internal/http/templates"
	grpcsts "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/types/known/emptypb"
)

type conn struct {
	emptyHTTP
	stt    grpcsts.ConnectionsServer
	server *websocket.Server
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

func (c *conn) Post(w http.ResponseWriter, r *http.Request) error {
	conns, err := c.stt.Conns(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	sort.Slice(conns.Connections, func(i, j int) bool { return conns.Connections[i].Id < conns.Connections[j].Id })
	return TPS.Execute(w, conns.GetConnections(), tps.CONNECTIONS)
}

func (cc *conn) Websocket(w http.ResponseWriter, r *http.Request) error {
	if cc.server == nil {
		cc.server = &websocket.Server{
			Handler: func(c *websocket.Conn) {
				defer c.Close()

				for {
					var tmp string
					err := websocket.Message.Receive(c, &tmp)
					if err != nil {
						break
					}

					total, err := cc.stt.Total(context.TODO(), &emptypb.Empty{})
					if err != nil {
						break
					}
					err = websocket.Message.Send(c, fmt.Sprintf(`{"download": %d, "upload": %d}`, total.Download, total.Upload))
					if err != nil {
						break
					}
				}
			},
		}
	}
	cc.server.ServeHTTP(w, r)
	return nil
}
