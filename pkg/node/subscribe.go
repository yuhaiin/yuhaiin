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
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/node/parser"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
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

func (s *Subscribe) Update(ctx context.Context, req *api.LinkReq) (*emptypb.Empty, error) {
	s.update(ctx, req.GetNames()...)
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

func (l *Subscribe) update(ctx context.Context, names ...string) {
	for _, str := range names {
		link, ok := l.n.GetLink(str)
		if !ok {
			continue
		}

		scheme, _, _ := system.GetScheme(link.GetUrl())
		var err error
		if scheme == "yuhaiin" {
			err = l.savePublish(ctx, link.GetUrl())
		} else {
			err = l.fetch(ctx, link)
		}
		if err != nil {
			log.Error("get one link failed", "err", err)
		}
	}
}

func (n *Subscribe) fetch(ctx context.Context, link *node.Link) error {
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

	req, err := http.NewRequestWithContext(ctx, "GET", link.GetUrl(), nil)
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

func (n *Subscribe) RemovePublish(ctx context.Context, in *wrapperspb.StringValue) (*emptypb.Empty, error) {
	n.n.DeletePublish(in.Value)
	return &emptypb.Empty{}, n.n.Save()
}

func (n *Subscribe) ListPublish(ctx context.Context, in *emptypb.Empty) (*api.ListPublishResponse, error) {
	return api.ListPublishResponse_builder{Publishes: n.n.GetPublishes()}.Build(), nil
}

func (n *Subscribe) SavePublish(ctx context.Context, in *api.SavePublishRequest) (*emptypb.Empty, error) {
	n.n.SavePublish(in.GetName(), in.GetPublish())
	return &emptypb.Empty{}, n.n.Save()
}

func (n *Subscribe) Publish(ctx context.Context, in *api.PublishRequest) (*api.PublishResponse, error) {
	return api.PublishResponse_builder{
		Points: n.n.Publish(in.GetName(), in.GetPath(), in.GetPassword()),
	}.Build(), nil
}

func (n *Subscribe) savePublish(ctx context.Context, url string) error {
	u := strings.TrimPrefix(url, "yuhaiin://")

	data, err := base64.RawURLEncoding.DecodeString(u)
	if err != nil {
		return err
	}

	yu := &node.YuhaiinUrl{}
	if err = proto.Unmarshal(data, yu); err != nil {
		return err
	}

	if yu.GetName() == "" {
		yu.SetName("default")
	}

	switch yu.WhichUrl() {
	case node.YuhaiinUrl_Points_case:
		n.n.SaveNode(yu.GetPoints().GetPoints()...)
	case node.YuhaiinUrl_Remote_case:
		u := yu.GetRemote().GetUrl()
		opts := []grpc.DialOption{
			grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
				ad, err := netapi.ParseAddress("tcp", s)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %w", err)
				}

				ctx = netapi.WithContext(ctx)

				return configuration.ProxyChain.Conn(ctx, ad)
			}),
		}
		if yu.GetRemote().GetInsecure() {
			opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}

		c, err := grpc.NewClient(u, opts...)
		if err != nil {
			return fmt.Errorf("new client failed: %w", err)
		}
		defer c.Close()

		sbc := api.NewSubscribeClient(c)

		resp, err := sbc.Publish(ctx, api.PublishRequest_builder{
			Name:     proto.String(yu.GetRemote().GetPublish().GetName()),
			Path:     proto.String(yu.GetRemote().GetPublish().GetPath()),
			Password: proto.String(yu.GetRemote().GetPublish().GetPassword()),
		}.Build())
		if err != nil {
			return fmt.Errorf("publish failed: %w", err)
		}

		for _, p := range resp.GetPoints() {
			p.SetOrigin(node.Origin_remote)
			p.SetGroup(yu.GetName())
		}

		n.n.SaveNode(resp.GetPoints()...)

	default:
		return fmt.Errorf("unknown url type")
	}

	return n.n.Save()
}
