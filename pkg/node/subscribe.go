package node

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/node/parser"
	"github.com/Asutorufa/yuhaiin/pkg/schema/api"
	"github.com/Asutorufa/yuhaiin/pkg/schema/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type Subscribe struct {
	n *Manager
}

func (s *Subscribe) Save(_ context.Context, l *api.SaveLinkReq) (*api.Empty, error) {
	return &api.Empty{}, s.save(l.GetLinks())
}

func (s *Subscribe) Remove(_ context.Context, l *api.LinkReq) (*api.Empty, error) {
	return &api.Empty{}, s.n.DeleteLink(l.GetNames()...)
}

func (s *Subscribe) Update(ctx context.Context, req *api.LinkReq) (*api.Empty, error) {
	return &api.Empty{}, s.update(ctx, req.GetNames()...)
}

func (s *Subscribe) Get(context.Context, *api.Empty) (*api.GetLinksResp, error) {
	return api.GetLinksResp_builder{Links: s.n.GetLinks()}.Build(), nil
}

func (l *Subscribe) save(ls []*node.Link) error {
	nodes := []*node.Point{}
	links := []*node.Link{}

	for _, z := range ls {
		pp, err := parser.ParseUrl([]byte(z.GetUrl()), node.Link_builder{Name: new(z.GetName())}.Build())
		if err == nil {
			pp.SetOrigin(node.Origin_manual)
			nodes = append(nodes, pp) // link is a node
		} else {
			links = append(links, z) // link is a subscription
		}
	}

	return errors.Join(l.n.SaveLinks(links...), l.n.SaveNode(nodes...))
}

func (l *Subscribe) update(ctx context.Context, names ...string) error {
	var errs error
	for _, str := range names {
		link, ok := l.n.GetLink(str)
		if !ok {
			continue
		}

		scheme, _, _ := system.GetScheme(link.GetUrl())
		var err error
		if scheme == "yuhaiin" {
			err = l.savePublish(ctx, link)
		} else {
			err = l.fetch(ctx, link)
		}
		if err != nil {
			log.Error("get one link failed", "err", err)
			errs = errors.Join(errs, err)
		}
	}
	return errs
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

	if err := scanner.Err(); err != nil {
		return err
	}

	return n.n.ReplaceRemoteNodes(link.GetName(), nodes...)
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

func (n *Subscribe) RemovePublish(ctx context.Context, in *api.StringValue) (*api.Empty, error) {
	return &api.Empty{}, n.n.DeletePublish(in.Value)
}

func (n *Subscribe) ListPublish(ctx context.Context, in *api.Empty) (*api.ListPublishResponse, error) {
	return api.ListPublishResponse_builder{Publishes: n.n.GetPublishes()}.Build(), nil
}

func (n *Subscribe) SavePublish(ctx context.Context, in *api.SavePublishRequest) (*api.Empty, error) {
	return &api.Empty{}, n.n.SavePublish(in.GetName(), in.GetPublish())
}

func (n *Subscribe) Publish(ctx context.Context, in *api.PublishRequest) (*api.PublishResponse, error) {
	return api.PublishResponse_builder{
		Points: n.n.Publish(in.GetName(), in.GetPath(), in.GetPassword()),
	}.Build(), nil
}

func (n *Subscribe) savePublish(ctx context.Context, link *node.Link) error {
	u := strings.TrimPrefix(link.GetUrl(), "yuhaiin://")

	data, err := base64.RawURLEncoding.DecodeString(u)
	if err != nil {
		return err
	}

	yu := &node.YuhaiinUrl{}
	if err = json.Unmarshal(data, yu); err != nil {
		return err
	}

	if yu.GetName() == "" {
		yu.SetName("default")
	}

	switch yu.WhichUrl() {
	case node.YuhaiinUrl_Points_case:
		return n.n.ReplaceRemoteNodes(link.GetName(), yu.GetPoints().GetPoints()...)
	case node.YuhaiinUrl_Remote_case:
		publish := yu.GetRemote().GetPublish()
		u := publish.GetAddress()
		if _, port, _ := net.SplitHostPort(u); port == "" {
			if yu.GetRemote().GetPublish().GetInsecure() {
				u = net.JoinHostPort(u, "80")
			} else {
				u = net.JoinHostPort(u, "443")
			}
		}

		scheme := "https"
		if publish.GetInsecure() {
			scheme = "http"
		}
		endpoint := url.URL{
			Scheme: scheme,
			Host:   u,
			Path:   "/api/v1/publishes/" + url.PathEscape(publish.GetName()) + ":resolve",
		}

		hc := &http.Client{
			Timeout: time.Minute * 2,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					ad, err := netapi.ParseAddress(network, addr)
					if err != nil {
						return nil, fmt.Errorf("parse address failed: %w", err)
					}

					ctx = netapi.WithContext(ctx)

					log.Info("subscription http dial", "addr", ad)
					return configuration.ProxyChain.Conn(ctx, ad)
				},
			},
		}

		body := map[string]string{
			"path":     publish.GetPath(),
			"password": publish.GetPassword(),
		}
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal publish request failed: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("create publish request failed: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		res, err := hc.Do(req)
		if err != nil {
			return fmt.Errorf("publish request failed: %w", err)
		}
		defer res.Body.Close()

		if res.StatusCode < 200 || res.StatusCode >= 300 {
			msg, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
			return fmt.Errorf("publish request failed: status=%d body=%s", res.StatusCode, strings.TrimSpace(string(msg)))
		}

		data, err := io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("read publish response failed: %w", err)
		}

		resp := &api.PublishResponse{}
		if err := json.Unmarshal(data, resp); err != nil {
			return fmt.Errorf("decode publish response failed: %w", err)
		}

		return n.n.ReplaceRemoteNodes(link.GetName(), resp.GetPoints()...)

	default:
		return fmt.Errorf("unknown url type")
	}
}
