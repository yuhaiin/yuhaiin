package simplehttp

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

//go:embed statistic.js
var statisticJS []byte

func initStatistic(mux *http.ServeMux, stt statistic.ConnectionsServer) {
	mux.HandleFunc("/conn/list", func(w http.ResponseWriter, r *http.Request) {
		conns, err := stt.Conns(context.TODO(), &emptypb.Empty{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sort.Slice(conns.Connections, func(i, j int) bool { return conns.Connections[i].Id < conns.Connections[j].Id })

		str := strings.Builder{}
		str.WriteString(fmt.Sprintf(`<script>%s</script>`, statisticJS))
		str.WriteString(`<pre id="statistic">Loading...</pre>`)
		str.WriteString("<hr/>")

		for _, c := range conns.GetConnections() {
			str.WriteString("<p>")
			str.WriteString(fmt.Sprintf(`<a>%d| &lt;%s[%s]&gt; %s, %s <-> %s</a>`, c.GetId(), c.GetType(), c.GetMark(), c.GetAddr(), c.GetLocal(), c.GetRemote()))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='/conn/close?id=%d'>Close</a>`, c.GetId()))
			str.WriteString("</p>")
		}

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

		http.Redirect(w, r, "/conn/list", http.StatusFound)
	})

	var upgrader = websocket.Upgrader{} // use default options

	mux.HandleFunc("/statistic", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer c.Close()

		ctx, cancel := context.WithCancel(context.TODO())
		go func() {
			_, _, err := c.ReadMessage()
			if err != nil {
				cancel()
			}
		}()

		stt.Statistic(&emptypb.Empty{}, newStatisticSend(ctx, func(rr *statistic.RateResp) error {
			data, _ := protojson.Marshal(rr)
			err = c.WriteMessage(websocket.TextMessage, data)
			if err != nil {
				cancel()
			}

			return err
		}))
	})
}

var _ statistic.Connections_StatisticServer = &statisticSend{}

type statisticSend struct {
	grpc.ServerStream
	send func(*statistic.RateResp) error
	ctx  context.Context
}

func newStatisticSend(ctx context.Context, send func(*statistic.RateResp) error) *statisticSend {
	return &statisticSend{ctx: ctx, send: send}
}

func (s *statisticSend) Send(statistic *statistic.RateResp) error {
	return s.send(statistic)
}

func (s *statisticSend) Context() context.Context {
	return s.ctx
}
