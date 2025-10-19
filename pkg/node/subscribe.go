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
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Subscribe struct {
	api.UnimplementedSubscribeServer

	n *Manager
}

func (s *Subscribe) Save(_ context.Context, l *api.SaveLinkReq) (*emptypb.Empty, error) {
	s.save(l.GetLinks())
	return &emptypb.Empty{}, s.n.Save()
}

func (s *Subscribe) Remove(_ context.Context, l *api.LinkReq) (*emptypb.Empty, error) {
	s.n.DeleteLink(l.GetNames()...)
	return &emptypb.Empty{}, s.n.Save()
}

func (s *Subscribe) Update(_ context.Context, req *api.LinkReq) (*emptypb.Empty, error) {
	s.update(req.GetNames()...)
	return &emptypb.Empty{}, s.n.Save()
}

func (s *Subscribe) Get(context.Context, *emptypb.Empty) (*api.GetLinksResp, error) {
	return api.GetLinksResp_builder{Links: s.n.GetLinks()}.Build(), nil
}

func (l *Subscribe) save(ls []*node.Link) {
	nodes := []*node.Point{}
	links := []*node.Link{}

	for _, z := range ls {
		pp, err := parser.ParseUrl([]byte(z.GetUrl()), node.Link_builder{Name: proto.String(z.GetName())}.Build())
		if err == nil {
			pp.SetOrigin(node.Origin_manual)
			nodes = append(nodes, pp) // link is a node
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

func (n *Subscribe) fetch(link *node.Link) error {
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
	var nodes []*node.Point
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}

		pp, err := parser.ParseUrl(scanner.Bytes(), link)
		if err != nil {
			log.Error("parse url failed", slog.String("url", scanner.Text()), slog.Any("err", err))
		} else {
			pp.SetOrigin(node.Origin(*node.Origin_remote.Enum()))
			nodes = append(nodes, pp)
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
