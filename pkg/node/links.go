package node

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/node/parser"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	"github.com/Asutorufa/yuhaiin/pkg/utils"
	"golang.org/x/exp/slog"
)

type link struct {
	outbound *outbound
	manager  *manager

	links map[string]*subscribe.Link
	mu    sync.RWMutex
}

func NewLink(outbound *outbound, manager *manager, links map[string]*subscribe.Link) *link {
	return &link{outbound: outbound, manager: manager, links: links}
}

func (l *link) Save(ls []*subscribe.Link) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.links == nil {
		l.links = make(map[string]*subscribe.Link)
	}

	for _, z := range ls {

		node, err := parseUrl([]byte(z.Url), &subscribe.Link{Name: z.Name})
		if err == nil {
			l.addNode(node) // link is a node
		} else {
			l.links[z.Name] = z // link is a subscription
		}

	}
}

func (l *link) Delete(names []string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, z := range names {
		delete(l.links, z)
	}
}

func (l *link) Links() map[string]*subscribe.Link { return l.links }

func (n *link) Update(names []string) {
	if n.links == nil {
		n.links = make(map[string]*subscribe.Link)
	}

	wg := sync.WaitGroup{}
	for _, l := range names {
		l, ok := n.links[l]
		if !ok {
			continue
		}

		wg.Add(1)
		go func(l *subscribe.Link) {
			defer wg.Done()
			if err := n.update(n.outbound.Do, l); err != nil {
				log.Error("get one link failed", "err", err)
			}
		}(l)
	}

	wg.Wait()

	oo := n.outbound.UDP
	if p, ok := n.manager.GetNodeByName(oo.Group, oo.Name); ok {
		n.outbound.Save(p, true)
	}

	oo = n.outbound.TCP
	if p, ok := n.manager.GetNodeByName(oo.Group, oo.Name); ok {
		n.outbound.Save(p, false)
	}
}

func (n *link) update(do func(*http.Request) (*http.Response, error), link *subscribe.Link) error {
	req, err := http.NewRequest("GET", link.Url, nil)
	if err != nil {
		return fmt.Errorf("create request failed: %w", err)
	}

	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s-%s", version.AppName, version.Version, version.GitCommit))

	res, err := do(req)
	if err != nil {
		return fmt.Errorf("get %s failed: %w", link.Name, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read body failed: %w", err)
	}

	dst := make([]byte, base64.RawStdEncoding.DecodedLen(len(body)))
	if _, err = base64.RawStdEncoding.Decode(dst, bytes.TrimRight(body, "=")); err != nil {
		return fmt.Errorf("decode body failed: %w, body: %v", err, string(body))
	}

	n.manager.DeleteRemoteNodes(link.Name)

	for _, x := range bytes.Split(dst, []byte("\n")) {
		node, err := parseUrl(x, link)
		if err != nil {
			log.Error("parse url failed", slog.String("url", string(x)), slog.Any("err", err))
		} else {
			n.addNode(node)
		}
	}

	return nil
}

func (n *link) addNode(node *point.Point) {
	n.manager.DeleteNode(node.Hash)
	n.manager.AddNode(node)
}

var schemeTypeMap = map[string]subscribe.Type{
	"ss":     subscribe.Type_shadowsocks,
	"ssr":    subscribe.Type_shadowsocksr,
	"vmess":  subscribe.Type_vmess,
	"trojan": subscribe.Type_trojan,
}

func parseUrl(str []byte, l *subscribe.Link) (no *point.Point, err error) {
	t := l.Type

	if t == subscribe.Type_reserve {
		scheme, _, _ := utils.GetScheme(string(str))
		t = schemeTypeMap[scheme]
	}

	no, err = parser.Parse(t, str)
	if err != nil {
		return nil, fmt.Errorf("parse link data failed: %w", err)
	}
	no.Group = l.Name
	return no, nil
}
