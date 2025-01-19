package route

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"unique"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"google.golang.org/protobuf/proto"
)

type routeParser struct {
	rules       []*bypass.RemoteRule
	proxy       netapi.Proxy
	path        string
	trie        *routeTries
	forceUpdate bool
}

func parseTrie(path string, proxy netapi.Proxy, rules []*bypass.RemoteRule, force bool) *routeTries {
	r := &routeParser{
		proxy:       proxy,
		path:        path,
		rules:       rules,
		trie:        newRouteTires(),
		forceUpdate: force,
	}

	r.Trie()

	return r.trie
}

func getRemote(path string, proxy netapi.Proxy, url string, force bool) (io.ReadCloser, error) {
	r := &routeParser{
		proxy:       proxy,
		path:        path,
		forceUpdate: force,
	}

	re, err := r.getReader((&bypass.RemoteRule_builder{
		Enabled: proto.Bool(true),
		Name:    proto.String(url),
		Http: (&bypass.RemoteRuleHttp_builder{
			Url: proto.String(url),
		}).Build(),
	}).Build())

	return re, err
}

func (r *routeParser) Trie() {
	for _, rule := range r.rules {
		if !rule.GetEnabled() {
			continue
		}

		rc, err := r.getReader(rule)
		if err != nil {
			rule.SetErrorMsg(err.Error())
			log.Error("get reader failed", slog.Any("err", err), slog.Any("rule", rule))
			continue
		}

		rule.SetErrorMsg("")
		r.insert(rc)
	}
}

func (r *routeParser) getReader(rule *bypass.RemoteRule) (io.ReadCloser, error) {
	path := ""
	switch rule.WhichObject() {
	case bypass.RemoteRule_Http_case:
		if rule.GetHttp().GetUrl() == "" {
			return nil, fmt.Errorf("empty url")
		}

		path = filepath.Join(r.path, hexName(rule.GetName(), rule.GetHttp().GetUrl()))

		updated := r.forceUpdate
		if !updated {
			if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
				updated = true
			}
		}

		if updated {
			if err := r.saveRemote(path, rule.GetHttp().GetUrl()); err != nil {
				return nil, fmt.Errorf("save remote failed: %w", err)
			}
		}

	case bypass.RemoteRule_File_case:
		if rule.GetFile().GetPath() == "" {
			return nil, fmt.Errorf("empty path")
		}

		path = rule.GetFile().GetPath()
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return f, nil
}

func (r *routeParser) saveRemote(path, url string) error {
	err := os.MkdirAll(filepath.Dir(path), os.ModePerm)
	if err != nil {
		return err
	}

	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(network, addr)
				if err != nil {
					return nil, err
				}

				return r.proxy.Conn(ctx, ad)
			},
		},
		Timeout: 30 * time.Second,
	}

	resp, err := hc.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status code: %d, data: %s", resp.StatusCode, string(data))
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func hexName(name, url string) string {
	h := sha256.New()

	_, _ = io.WriteString(h, name)
	_, _ = io.WriteString(h, url)

	return hex.EncodeToString(h.Sum(nil))
}

func (r *routeParser) insert(rc io.ReadCloser) {
	defer rc.Close()

	br := bufio.NewScanner(rc)

	for br.Scan() {
		uri, modeEnum, err := parseLine(br.Text())
		if err != nil {
			continue
		}

		r.trie.insert(uri, modeEnum)
	}
}

func parseLine(txt string) (*Uri, unique.Handle[bypass.ModeEnum], error) {
	before := TrimComment(txt)

	uri, args, ok := SplitHostArgs(before)
	if !ok {
		return nil, unique.Handle[bypass.ModeEnum]{}, fmt.Errorf("split host failed: %s", txt)
	}

	modeEnum, ok := SplitModeArgs(args)
	if !ok {
		return nil, unique.Handle[bypass.ModeEnum]{}, fmt.Errorf("split mode failed: %s", txt)
	}

	return uri, modeEnum, nil
}
