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
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type ParsedYuhaiinURL struct {
	Name   string
	Points []contractnode.Node
	Remote *contractsubscription.Publish
}

var subscriptionParsers struct {
	parseShareURL   func(data []byte, group, typ string) (contractnode.Node, error)
	parseYuhaiinURL func(raw string) (ParsedYuhaiinURL, error)
}

func RegisterSubscriptionParsers(
	parseShareURL func(data []byte, group, typ string) (contractnode.Node, error),
	parseYuhaiinURL func(raw string) (ParsedYuhaiinURL, error),
) {
	subscriptionParsers.parseShareURL = parseShareURL
	subscriptionParsers.parseYuhaiinURL = parseYuhaiinURL
}

type Subscribe struct {
	n             *Manager
	nodes         *plainstore.NodeStore
	subscriptions *plainstore.SubscriptionStore
}

func NewSubscribe(manager *Manager, nodes *plainstore.NodeStore, subscriptions *plainstore.SubscriptionStore) *Subscribe {
	return &Subscribe{
		n:             manager,
		nodes:         nodes,
		subscriptions: subscriptions,
	}
}

func (l *Subscribe) update(ctx context.Context, names ...string) error {
	if l == nil || l.subscriptions == nil {
		return errors.New("subscription store is unavailable")
	}
	if len(names) == 0 {
		links, err := l.subscriptions.ListLinks(ctx)
		if err != nil {
			return err
		}
		names = make([]string, 0, len(links.Items))
		for _, link := range links.Items {
			names = append(names, link.Name)
		}
	}

	var errs error
	for _, name := range names {
		link, ok, err := l.subscriptions.GetLink(ctx, name)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		if !ok {
			continue
		}

		scheme, _, _ := system.GetScheme(link.URL)
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

func (n *Subscribe) fetch(ctx context.Context, link contractsubscription.Link) error {
	hc := subscriptionHTTPClient()

	req, err := http.NewRequestWithContext(ctx, "GET", link.URL, nil)
	if err != nil {
		return fmt.Errorf("create request failed: %w", err)
	}
	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s-%s", version.AppName, version.Version, version.GitCommit))

	res, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("get %s failed: %w", link.Name, err)
	}
	defer res.Body.Close()

	base64r := base64.NewDecoder(base64.RawStdEncoding, &trimBase64Reader{res.Body})
	scanner := bufio.NewScanner(base64r)
	var nodes []contractnode.Node
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}

		if subscriptionParsers.parseShareURL == nil {
			return errors.New("subscription parser is not registered")
		}
		node, err := subscriptionParsers.parseShareURL(scanner.Bytes(), link.Name, link.Type)
		if err != nil {
			log.Error("parse url failed", slog.String("url", scanner.Text()), slog.Any("err", err))
		} else {
			node.Group = link.Name
			node.Origin = "remote"
			nodes = append(nodes, node)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return n.n.ReplaceRemoteContractNodes(link.Name, nodes)
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

func (n *Subscribe) savePublish(ctx context.Context, link contractsubscription.Link) error {
	if subscriptionParsers.parseYuhaiinURL == nil {
		return errors.New("subscription parser is not registered")
	}
	yu, err := subscriptionParsers.parseYuhaiinURL(link.URL)
	if err != nil {
		return err
	}

	if len(yu.Points) > 0 {
		return n.n.ReplaceRemoteContractNodes(link.Name, yu.Points)
	}
	if yu.Remote == nil {
		return nil
	}

	nodes, err := n.resolveRemotePublish(ctx, *yu.Remote)
	if err != nil {
		return err
	}
	return n.n.ReplaceRemoteContractNodes(link.Name, nodes)
}

func (n *Subscribe) resolveRemotePublish(ctx context.Context, publish contractsubscription.Publish) ([]contractnode.Node, error) {
	u := publish.Address
	if _, port, _ := net.SplitHostPort(u); port == "" {
		if publish.Insecure {
			u = net.JoinHostPort(u, "80")
		} else {
			u = net.JoinHostPort(u, "443")
		}
	}

	scheme := "https"
	if publish.Insecure {
		scheme = "http"
	}
	endpoint := url.URL{
		Scheme: scheme,
		Host:   u,
		Path:   "/api/v2/publishes/" + url.PathEscape(publish.Name) + "/resolve",
	}

	body := contractsubscription.ResolvePublishRequest{
		Path:     publish.Path,
		Password: publish.Password,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal publish request failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create publish request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := subscriptionHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("publish request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("publish request failed: status=%d body=%s", res.StatusCode, strings.TrimSpace(string(msg)))
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("read publish response failed: %w", err)
	}

	var resp contractsubscription.ResolvePublishResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("decode publish response failed: %w", err)
	}
	return resp.Points, nil
}

func (s *Subscribe) ResolvePublishContract(ctx context.Context, name string, req contractsubscription.ResolvePublishRequest) (contractsubscription.ResolvePublishResponse, error) {
	if s == nil || s.subscriptions == nil {
		return contractsubscription.ResolvePublishResponse{}, errors.New("subscription store is unavailable")
	}
	return s.subscriptions.ResolvePublish(ctx, name, req.Path, req.Password)
}

func subscriptionHTTPClient() *http.Client {
	return &http.Client{
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
}
