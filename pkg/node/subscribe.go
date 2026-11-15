package node

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
	"io"
	"mime"
	"net"
	"net/http"
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
}

// ErrLegacyPublishLink rejects yuhaiin:// links that pointed at the publish
// feature which share feeds replaced.
var ErrLegacyPublishLink = errors.New("this yuhaiin:// link points to a retired publish configuration; ask the publisher for a share feed link")

// maxSubscriptionBody bounds one subscription response.
const maxSubscriptionBody = 32 << 20

type Subscribe struct {
	runtime       *NodeRuntime
	subscriptions *plainstore.SubscriptionStore
}

func NewSubscribe(runtime *NodeRuntime, subscriptions *plainstore.SubscriptionStore) *Subscribe {
	return &Subscribe{
		runtime:       runtime,
		subscriptions: subscriptions,
	}
}

func (s *Subscribe) Update(ctx context.Context, names []string) error {
	if s == nil || s.subscriptions == nil {
		return errors.New("subscription store is unavailable")
	}
	if len(names) == 0 {
		links, err := s.subscriptions.ListLinks(ctx)
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
		link, ok, err := s.subscriptions.GetLink(ctx, name)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		if !ok {
			continue
		}

		scheme, _, _ := system.GetScheme(link.URL)
		if scheme == "yuhaiin" {
			err = s.savePublish(ctx, link)
		} else {
			err = s.fetch(ctx, link)
		}
		if err != nil {
			log.Error("get one link failed", "err", err)
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

// newSubscriptionClient is replaced by tests, which have no proxy chain.
var newSubscriptionClient = subscriptionHTTPClient

func (n *Subscribe) fetch(ctx context.Context, link contractsubscription.Link) error {
	hc := newSubscriptionClient()

	req, err := http.NewRequestWithContext(ctx, "GET", link.URL, nil)
	if err != nil {
		return fmt.Errorf("create request failed: %w", secret.RemoteError(err))
	}
	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s-%s", version.AppName, version.Version, version.GitCommit))
	req.Header.Set("Accept", contractsubscription.ShareFeedContentType+", */*;q=0.5")

	res, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("get %s failed: %w", link.Name, secret.RemoteError(err))
	}
	defer res.Body.Close()

	// A failed fetch must never replace the nodes from the last good one.
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("get %s failed: status=%d", link.Name, res.StatusCode)
	}
	body := io.LimitReader(res.Body, maxSubscriptionBody+1)

	var nodes []contractnode.Node
	if isShareFeedResponse(res.Header.Get("Content-Type")) {
		nodes, err = readShareFeed(body)
		if err != nil {
			return fmt.Errorf("read share feed %s failed: %w", link.Name, err)
		}
	} else {
		nodes, err = readBase64Subscription(body, link)
		if err != nil {
			return err
		}
		// An empty share-link list is far more often an error page or an expired
		// account than an intentional empty subscription.
		if len(nodes) == 0 {
			return fmt.Errorf("subscription %s returned no usable nodes", link.Name)
		}
	}
	for i := range nodes {
		nodes[i].Group = link.Name
		nodes[i].Origin = "remote"
	}
	return n.runtime.ReplaceRemoteContractNodes(ctx, link.Name, nodes)
}

func isShareFeedResponse(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == contractsubscription.ShareFeedContentType
}

// readShareFeed decodes a share feed. An empty node list is the publisher's
// current selection and replaces the group like any other.
func readShareFeed(r io.Reader) ([]contractnode.Node, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(data) > maxSubscriptionBody {
		return nil, errors.New("share feed is too large")
	}
	var document struct {
		Version int              `json:"version"`
		Nodes   []jsontext.Value `json:"nodes"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, errors.New("invalid share feed document")
	}
	if document.Version != 1 {
		return nil, fmt.Errorf("unsupported share feed version %d", document.Version)
	}
	nodes := make([]contractnode.Node, 0, len(document.Nodes))
	for _, raw := range document.Nodes {
		node, err := decodeSharedPoint([]byte(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid node in share feed: %w", err)
		}
		node.Enabled = true
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func readBase64Subscription(r io.Reader, link contractsubscription.Link) ([]contractnode.Node, error) {
	base64r := base64.NewDecoder(base64.RawStdEncoding, &trimBase64Reader{r})
	scanner := bufio.NewScanner(base64r)
	var nodes []contractnode.Node
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}

		node, err := parseShareURL(scanner.Bytes(), link.Name, link.Type)
		if err != nil {
			log.Error("parse subscription entry failed")
		} else {
			nodes = append(nodes, node)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nodes, nil
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
	yu, err := parseYuhaiinURL(link.URL)
	if err != nil {
		return err
	}
	return n.runtime.ReplaceRemoteContractNodes(ctx, link.Name, yu.Points)
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
