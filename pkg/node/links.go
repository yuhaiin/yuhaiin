package node

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/node/parser"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"github.com/Asutorufa/yuhaiin/pkg/utils/net"
)

type link struct {
	outbound *outbound
	manager  *manager

	db *jsondb.DB[*node.Node]

	mu sync.RWMutex
}

func NewLink(db *jsondb.DB[*node.Node], outbound *outbound, manager *manager) *link {
	return &link{outbound: outbound, manager: manager, db: db}
}

func (l *link) Save(ls []*subscribe.Link) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.db.Data.Links == nil {
		l.db.Data.Links = make(map[string]*subscribe.Link)
	}

	for _, z := range ls {

		node, err := parseUrl([]byte(z.Url), &subscribe.Link{Name: z.Name})
		if err == nil {
			l.addNode(node) // link is a node
		} else {
			l.db.Data.Links[z.Name] = z // link is a subscription
		}

	}
}

func (l *link) Delete(names []string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, z := range names {
		delete(l.db.Data.Links, z)
	}
}

func (l *link) Links() map[string]*subscribe.Link { return l.db.Data.Links }

func (l *link) Update(names []string) {
	if l.db.Data.Links == nil {
		l.db.Data.Links = make(map[string]*subscribe.Link)
	}

	wg := sync.WaitGroup{}
	for _, str := range names {
		link, ok := l.db.Data.Links[str]
		if !ok {
			continue
		}

		wg.Add(1)
		go func(link *subscribe.Link) {
			defer wg.Done()
			if err := l.update(l.outbound.Do, link); err != nil {
				log.Error("get one link failed", "err", err)
			}
		}(link)
	}

	wg.Wait()

	oo := l.db.Data.Udp
	if p, ok := l.manager.GetNodeByName(oo.Group, oo.Name); ok {
		l.db.Data.Udp = p
	}

	oo = l.db.Data.Tcp
	if p, ok := l.manager.GetNodeByName(oo.Group, oo.Name); ok {
		l.db.Data.Tcp = p
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

	n.manager.DeleteRemoteNodes(link.Name)

	base64r := base64.NewDecoder(base64.RawStdEncoding, &trimBase64Reader{res.Body})
	scanner := bufio.NewScanner(base64r)
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}

		node, err := parseUrl(scanner.Bytes(), link)
		if err != nil {
			log.Error("parse url failed", slog.String("url", scanner.Text()), slog.Any("err", err))
		} else {
			n.addNode(node)
		}
	}

	return scanner.Err()
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
		scheme, _, _ := net.GetScheme(string(str))
		t = schemeTypeMap[scheme]
	}

	no, err = parser.Parse(t, str)
	if err != nil {
		return nil, fmt.Errorf("parse link data failed: %w", err)
	}
	no.Group = l.Name
	return no, nil
}
