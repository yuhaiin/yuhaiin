package simplehttp

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"golang.org/x/net/websocket"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

//go:embed statistic.js
var statisticJS []byte

func initStatistic(mux *http.ServeMux, stt statistic.ConnectionsServer) {
	mux.HandleFunc("/conn/list", func(w http.ResponseWriter, r *http.Request) {
		str := utils.GetBuffer()
		defer utils.PutBuffer(str)

		str.WriteString(fmt.Sprintf(`<script>%s</script>`, statisticJS))
		str.WriteString(`<pre id="statistic">Loading...</pre>`)
		str.WriteString("<hr/>")

		str.WriteString(`<a href="javascript: refresh()">Refresh</a>`)
		str.WriteString(`<p id="connections"></p>`)

		w.Write([]byte(createHTML(str.String())))
	})

	mux.HandleFunc("/conn/close", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")

		i, err := strconv.Atoi(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = stt.CloseConn(context.TODO(), &statistic.CloseConnsReq{Conns: []int64{int64(i)}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("OK"))
	})

	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		conns, err := stt.Conns(context.TODO(), &emptypb.Empty{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sort.Slice(conns.Connections, func(i, j int) bool { return conns.Connections[i].Id < conns.Connections[j].Id })

		str := utils.GetBuffer()
		defer utils.PutBuffer(str)

		for _, c := range conns.GetConnections() {
			str.WriteString("<p>")
			str.WriteString(fmt.Sprintf(`<a>%d| &lt;%s[%s]&gt; %s, %s <-> %s</a>`, c.GetId(), c.GetType(), c.GetMark(), c.GetAddr(), c.GetLocal(), c.GetRemote()))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='javascript: close("%d")'>Close</a>`, c.GetId()))
			str.WriteString("</p>")
		}

		w.Write(str.Bytes())
	})

	var server *websocket.Server
	mux.HandleFunc("/statistic", func(w http.ResponseWriter, r *http.Request) {
		if server != nil {
			server.ServeHTTP(w, r)
			return
		}

		server = &websocket.Server{
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

				stt.Statistic(
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
		server.ServeHTTP(w, r)
	})
}

var _ statistic.Connections_StatisticServer = &statisticServer{}

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
func (s *statisticServer) SendMsg(m interface{}) error  { return errNotImpl }
func (s *statisticServer) RecvMsg(m interface{}) error  { return errNotImpl }
