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
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Subscribe struct {
	gn.UnimplementedSubscribeServer

	n *Manager
}

func (s *Subscribe) Save(_ context.Context, l *gn.SaveLinkReq) (*emptypb.Empty, error) {
	s.n.Links().Save(l.GetLinks())
	return &emptypb.Empty{}, s.n.Save()
}

func (s *Subscribe) Remove(_ context.Context, l *gn.LinkReq) (*emptypb.Empty, error) {
	s.n.Links().Delete(l.GetNames()...)
	return &emptypb.Empty{}, s.n.Save()
}

func (s *Subscribe) Update(_ context.Context, req *gn.LinkReq) (*emptypb.Empty, error) {
	s.n.Links().Update(req.GetNames()...)
	return &emptypb.Empty{}, s.n.Save()
}

func (s *Subscribe) Get(context.Context, *emptypb.Empty) (*gn.GetLinksResp, error) {
	return gn.GetLinksResp_builder{Links: s.n.GetLinks()}.Build(), nil
}

type link struct {
	manager *Manager
}

func (l *link) Save(ls []*subscribe.Link) {
	nodes := []*point.Point{}
	links := []*subscribe.Link{}

	for _, z := range ls {
		node, err := parseUrl([]byte(z.GetUrl()), subscribe.Link_builder{Name: proto.String(z.GetName())}.Build())
		if err == nil {
			node.SetOrigin(point.Origin_manual)
			nodes = append(nodes, node) // link is a node
		} else {
			links = append(links, z) // link is a subscription
		}
	}

	l.manager.SaveLinks(links...)
	l.manager.SaveNode(nodes...)
}

func (l *link) Delete(names ...string) { l.manager.DeleteLink(names...) }

func (l *link) Update(names ...string) {
	for _, str := range names {
		link, ok := l.manager.GetLink(str)
		if !ok {
			continue
		}

		if err := l.update(link); err != nil {
			log.Error("get one link failed", "err", err)
		}
	}
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

func (n *link) update(link *subscribe.Link) error {
	hc := &http.Client{
		Timeout: time.Minute * 2,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(network, addr)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %w", err)
				}

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

		node, err := parseUrl(scanner.Bytes(), link)
		if err != nil {
			log.Error("parse url failed", slog.String("url", scanner.Text()), slog.Any("err", err))
		} else {
			node.SetOrigin(point.Origin_remote)
			nodes = append(nodes, node)
		}
	}

	n.manager.DeleteRemoteNodes(link.GetName())
	n.manager.SaveNode(nodes...)
	return scanner.Err()
}

func parseUrl(str []byte, l *subscribe.Link) (no *point.Point, err error) {
	var schemeTypeMap = map[string]subscribe.Type{
		"ss":     subscribe.Type_shadowsocks,
		"ssr":    subscribe.Type_shadowsocksr,
		"vmess":  subscribe.Type_vmess,
		"trojan": subscribe.Type_trojan,
	}

	t := l.GetType()

	if t == subscribe.Type_reserve {
		scheme, _, _ := system.GetScheme(string(str))
		t = schemeTypeMap[scheme]
	}

	no, err = parser.Parse(t, str)
	if err != nil {
		return nil, fmt.Errorf("parse link data failed: %w", err)
	}
	no.SetGroup(l.GetName())
	return no, nil
}
