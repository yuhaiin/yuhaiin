package simplehttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/internal/router"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	grpcsts "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"golang.org/x/net/websocket"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

type conn struct {
	emptyHTTP
	stt    grpcsts.ConnectionsServer
	server *websocket.Server
}

func (c *conn) Delete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	i, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = c.stt.CloseConn(context.TODO(), &statistic.CloseConnsReq{Conns: []int64{int64(i)}})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("OK"))
}

func (c *conn) Get(w http.ResponseWriter, r *http.Request) {
	str := utils.GetBuffer()
	defer utils.PutBuffer(str)

	str.WriteString(fmt.Sprintf(`<script>%s</script>`, statisticJS))
	str.WriteString(`<pre id="statistic">Loading...</pre>`)
	str.WriteString("<hr/>")

	str.WriteString(`<a href="javascript: refresh()">Refresh</a>`)
	str.WriteString(`<p id="connections"></p>`)

	w.Write([]byte(createHTML(str.String())))
}

func (c *conn) Post(w http.ResponseWriter, r *http.Request) {
	conns, err := c.stt.Conns(context.TODO(), &emptypb.Empty{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sort.Slice(conns.Connections, func(i, j int) bool { return conns.Connections[i].Id < conns.Connections[j].Id })

	str := utils.GetBuffer()
	defer utils.PutBuffer(str)

	str.WriteString("<dl>")
	for _, c := range conns.GetConnections() {
		str.WriteString("<hr/>")
		str.WriteString(fmt.Sprintf("<dt>%d| &lt;%s[%s]&gt; %s ", c.Id, c.GetType(), c.GetExtra()[router.MODE_MARK], c.GetAddr()))
		str.WriteString(fmt.Sprintf(`<a href='javascript: close("%d")'>Close</a>`, c.GetId()))
		str.WriteString("</dt>")
		str.WriteString(fmt.Sprintf("<dd>src: %s</dd>", c.GetLocal()))
		str.WriteString(fmt.Sprintf("<dd>dst: %s</dd>", c.GetRemote()))
		for k, v := range c.GetExtra() {
			if k == router.MODE_MARK {
				continue
			}
			str.WriteString(fmt.Sprintf("<dd>%s: %s</dd>", k, v))
		}
	}

	str.WriteString("</dl>")
	w.Write(str.Bytes())
}

func (cc *conn) Websocket(w http.ResponseWriter, r *http.Request) {
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
							data, _ := protojson.Marshal(rr)
							err := websocket.Message.Send(c, *(*string)(unsafe.Pointer(&data)))
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
