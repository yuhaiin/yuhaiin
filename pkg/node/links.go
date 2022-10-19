package node

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/node/parser"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

type link struct {
	outbound *outbound
	manager  *manager

	links map[string]*node.NodeLink
	lock  sync.RWMutex
}

func NewLink(outbound *outbound, manager *manager, links map[string]*node.NodeLink) *link {
	return &link{outbound: outbound, manager: manager, links: links}
}

func (l *link) Save(ls []*node.NodeLink) {
	l.lock.Lock()
	defer l.lock.Unlock()

	if l.links == nil {
		l.links = make(map[string]*node.NodeLink)
	}

	for _, z := range ls {

		node, err := parseUrl([]byte(z.Url), &node.NodeLink{Name: z.Name})
		if err == nil {
			l.addNode(node) // link is a node
		} else {
			l.links[z.Name] = z // link is a subscription
		}

	}
}

func (l *link) Delete(names []string) {
	l.lock.Lock()
	defer l.lock.Unlock()

	for _, z := range names {
		delete(l.links, z)
	}
}

func (l *link) Links() map[string]*node.NodeLink { return l.links }

func (n *link) Update(names []string) {
	if n.links == nil {
		n.links = make(map[string]*node.NodeLink)
	}

	wg := sync.WaitGroup{}
	for _, l := range names {
		l, ok := n.links[l]
		if !ok {
			continue
		}

		wg.Add(1)
		go func(l *node.NodeLink) {
			defer wg.Done()
			if err := n.update(n.outbound.Do, l); err != nil {
				log.Errorf("get one link failed: %v", err)
			}
		}(l)
	}

	wg.Wait()
}

func (n *link) update(do func(*http.Request) (*http.Response, error), link *node.NodeLink) error {
	req, err := http.NewRequest("GET", link.Url, nil)
	if err != nil {
		return fmt.Errorf("create request failed: %v", err)
	}

	req.Header.Set("User-Agent", "yuhaiin")

	res, err := do(req)
	if err != nil {
		return fmt.Errorf("get %s failed: %v", link.Name, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read body failed: %v", err)
	}

	dst := make([]byte, base64.RawStdEncoding.DecodedLen(len(body)))
	if _, err = base64.RawStdEncoding.Decode(dst, bytes.TrimRight(body, "=")); err != nil {
		return fmt.Errorf("decode body failed: %w, body: %v", err, string(body))
	}

	n.manager.DeleteRemoteNodes(link.Name)

	for _, x := range bytes.Split(dst, []byte("\n")) {
		node, err := parseUrl(x, link)
		if err != nil {
			log.Errorf("parse url %s failed: %v\n", x, err)
		} else {
			n.addNode(node)
		}
	}

	return nil
}

func (n *link) addNode(node *node.Point) {
	n.manager.DeleteNode(node.Hash)
	refreshHash(node)
	n.manager.AddNode(node)
}

var schemeTypeMap = map[string]node.NodeLinkLinkType{
	"ss":     node.NodeLink_shadowsocks,
	"ssr":    node.NodeLink_shadowsocksr,
	"vmess":  node.NodeLink_vmess,
	"trojan": node.NodeLink_trojan,
}

func parseUrl(str []byte, l *node.NodeLink) (no *node.Point, err error) {
	t := l.Type

	if t == node.NodeLink_reserve {
		scheme, _, _ := utils.GetScheme(string(str))
		t = schemeTypeMap[scheme]
	}

	no, err = parser.Parse(t, str)
	if err != nil {
		return nil, fmt.Errorf("parse link data failed: %v", err)
	}
	refreshHash(no)
	no.Group = l.Name
	return no, nil
}
