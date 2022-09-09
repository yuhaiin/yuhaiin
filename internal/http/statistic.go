package simplehttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"

	tps "github.com/Asutorufa/yuhaiin/internal/http/templates"
	grpcsts "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"golang.org/x/net/websocket"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

type conn struct {
	emptyHTTP
	stt    grpcsts.ConnectionsServer
	server *websocket.Server
}

func (c *conn) Delete(w http.ResponseWriter, r *http.Request) error {
	id := r.URL.Query().Get("id")

	i, err := strconv.Atoi(id)
	if err != nil {
		return err
	}

	_, err = c.stt.CloseConn(context.TODO(), &statistic.CloseConnsReq{Conns: []int64{int64(i)}})
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
				ctx, cancel := context.WithCancel(context.TODO())
				go func() {
					var tmp string
					err := websocket.Message.Receive(c, &tmp)
					if err != nil {
						cancel()
					}
				}()

				cc.stt.Statistic(
					&emptypb.Empty{},
					&statisticServer{
						ctx,
						func(rr *statistic.RateResp) error {
							err := websocket.Message.Send(c, fmt.Sprintf(`{"download": %d, "upload": %d}`, rr.Download, rr.Upload))
							if err != nil {
								cancel()
							}
							return err
						},
					},
				)

			},
		}
	}
	cc.server.ServeHTTP(w, r)
	return nil
}

var _ grpcsts.Connections_StatisticServer = &statisticServer{}

type statisticServer struct {
	ctx  context.Context
	send func(*statistic.RateResp) error
}

func (s *statisticServer) Send(statistic *statistic.RateResp) error { return s.send(statistic) }
func (s *statisticServer) Context() context.Context                 { return s.ctx }

var errNotImpl = errors.New("not implemented")

func (s *statisticServer) SetHeader(metadata.MD) error  { return errNotImpl }
func (s *statisticServer) SendHeader(metadata.MD) error { return errNotImpl }
func (s *statisticServer) SetTrailer(metadata.MD)       {}
func (s *statisticServer) SendMsg(m any) error          { return errNotImpl }
func (s *statisticServer) RecvMsg(m any) error          { return errNotImpl }
