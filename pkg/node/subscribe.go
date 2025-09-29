package node

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/node/parser"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Subscribe struct {
	gn.UnimplementedSubscribeServer

	n *Manager
}

func (s *Subscribe) Save(_ context.Context, l *gn.SaveLinkReq) (*emptypb.Empty, error) {
	s.save(l.GetLinks())
	return &emptypb.Empty{}, s.n.Save()
}

func (s *Subscribe) Remove(_ context.Context, l *gn.LinkReq) (*emptypb.Empty, error) {
	s.n.DeleteLink(l.GetNames()...)
	return &emptypb.Empty{}, s.n.Save()
}

func (s *Subscribe) Update(_ context.Context, req *gn.LinkReq) (*emptypb.Empty, error) {
	s.update(req.GetNames()...)
	return &emptypb.Empty{}, s.n.Save()
}

func (s *Subscribe) Get(context.Context, *emptypb.Empty) (*gn.GetLinksResp, error) {
	return gn.GetLinksResp_builder{Links: s.n.GetLinks()}.Build(), nil
}

func (l *Subscribe) save(ls []*subscribe.Link) {
	nodes := []*point.Point{}
	links := []*subscribe.Link{}

	for _, z := range ls {
		node, err := parser.ParseUrl([]byte(z.GetUrl()), subscribe.Link_builder{Name: proto.String(z.GetName())}.Build())
		if err == nil {
			node.SetOrigin(point.Origin_manual)
			nodes = append(nodes, node) // link is a node
		} else {
			links = append(links, z) // link is a subscription
		}
	}

	l.n.SaveLinks(links...)
	l.n.SaveNode(nodes...)
}

func (l *Subscribe) update(names ...string) {
	for _, str := range names {
		link, ok := l.n.GetLink(str)
		if !ok {
			continue
		}

		if err := l.fetch(link); err != nil {
			log.Error("get one link failed", "err", err)
		}
	}
}

func (n *Subscribe) fetch(link *subscribe.Link) error {
	hc := &http.Client{
		Timeout: time.Minute * 2,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(network, addr)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %w", err)
				}

				ctx = netapi.WithContext(ctx)

				return configuration.ProxyChain.Conn(ctx, ad)
			},
		},
	}

	req, err := http.NewRequest("GET", link.GetUrl(), nil)
	if err != nil {
		return fmt.Errorf("create request failed: %w", err)
	}

	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s-%s", version.AppName, version.Version, version.GitCommit))

	res, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("get %s failed: %w", link.GetName(), err)
	}
	defer res.Body.Close()

	base64r := base64.NewDecoder(base64.RawStdEncoding, &trimBase64Reader{res.Body})
	scanner := bufio.NewScanner(base64r)
	var nodes []*point.Point
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}

		node, err := parser.ParseUrl(scanner.Bytes(), link)
		if err != nil {
			log.Error("parse url failed", slog.String("url", scanner.Text()), slog.Any("err", err))
		} else {
			node.SetOrigin(point.Origin_remote)
			nodes = append(nodes, node)
		}
	}

	n.n.DeleteRemoteNodes(link.GetName())
	n.n.SaveNode(nodes...)
	return scanner.Err()
}

type trimBase64Reader struct {
	r io.Reader
}

func (t *trimBase64Reader) Read(b []byte) (int, error) {
	n, err := t.r.Read(b)

	if n > 0 {
		if i := bytes.IndexByte(b[:n], '='); i > 0 {
			n = i
		}
	}

	return n, err
}
