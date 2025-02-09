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
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"google.golang.org/protobuf/proto"
)

type link struct {
	outbound *outbound
	manager  *Manager
}

func NewLink(outbound *outbound, manager *Manager) *link {
	return &link{outbound: outbound, manager: manager}
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

func (l *link) Delete(names []string) { l.manager.DeleteLink(names...) }

func (l *link) Update(names []string) {
	wg := sync.WaitGroup{}
	for _, str := range names {
		link, ok := l.manager.GetLink(str)
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
	req, err := http.NewRequest("GET", link.GetUrl(), nil)
	if err != nil {
		return fmt.Errorf("create request failed: %w", err)
	}

	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s-%s", version.AppName, version.Version, version.GitCommit))

	res, err := do(req)
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

var schemeTypeMap = map[string]subscribe.Type{
	"ss":     subscribe.Type_shadowsocks,
	"ssr":    subscribe.Type_shadowsocksr,
	"vmess":  subscribe.Type_vmess,
	"trojan": subscribe.Type_trojan,
}

func parseUrl(str []byte, l *subscribe.Link) (no *point.Point, err error) {
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
