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
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unique"

	"github.com/Asutorufa/yuhaiin/pkg/chore"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
)

type routeParser struct {
	proxy       netapi.Proxy
	trie        *routeTries
	path        string
	rules       []*config.RemoteRule
	forceUpdate bool
}

func parseTrie(path string, proxy netapi.Proxy, rules []*config.RemoteRule, force bool) *routeTries {
	r := &routeParser{
		proxy:       proxy,
		path:        path,
		rules:       rules,
		trie:        newRouteTires(),
		forceUpdate: force,
	}

	r.Trie(context.TODO())

	return r.trie
}

func parseRemoteRuleUrl(urlstr string) (*config.RemoteRule, error) {
	url, err := url.Parse(urlstr)
	if err != nil {
		return nil, err
	}

	rr := (&config.RemoteRule_builder{
		Enabled: proto.Bool(true),
		Name:    proto.String(urlstr),
		Http: (&config.RemoteRuleHttp_builder{
			Url: proto.String(urlstr),
		}).Build(),
	}).Build()

	if url.Scheme == "file" {
		if runtime.GOOS == "windows" {
			url.Path = strings.TrimPrefix(url.Path, "/")
		}
		rr.SetFile(config.RemoteRuleFile_builder{
			Path: proto.String(url.Path),
		}.Build())
	} else {
		rr.SetHttp(config.RemoteRuleHttp_builder{
			Url: proto.String(urlstr),
		}.Build())
	}

	return rr, nil
}

func getRemote(ctx context.Context, path string, proxy netapi.Proxy, urlstr string, force bool) (io.ReadCloser, error) {
	r := &routeParser{
		proxy:       proxy,
		path:        path,
		forceUpdate: force,
	}

	rr, err := parseRemoteRuleUrl(urlstr)
	if err != nil {
		return nil, err
	}

	return r.getReader(ctx, rr, true)
}

func getLocalCache(path string, urlstr string) (io.ReadCloser, error) {
	r := &routeParser{
		path: path,
	}

	rr, err := parseRemoteRuleUrl(urlstr)
	if err != nil {
		return nil, err
	}

	return r.getReader(context.TODO(), rr, false)
}

func (r *routeParser) Trie(ctx context.Context) {
	for _, rule := range r.rules {
		if !rule.GetEnabled() {
			continue
		}

		rc, err := r.getReader(ctx, rule, true)
		if err != nil {
			rule.SetErrorMsg(err.Error())
			log.Error("get reader failed", slog.Any("err", err), slog.Any("rule", rule))
			continue
		}

		rule.SetErrorMsg("")
		r.insert(rc)
	}
}

func (r *routeParser) getReader(ctx context.Context, rule *config.RemoteRule, fetchRemote bool) (io.ReadCloser, error) {
	path := ""
	switch rule.WhichObject() {
	case config.RemoteRule_Http_case:
		if rule.GetHttp().GetUrl() == "" {
			return nil, fmt.Errorf("empty url")
		}

		path = filepath.Join(r.path, hexName(rule.GetName(), rule.GetHttp().GetUrl()))

		if !fetchRemote {
			break
		}

		updated := r.forceUpdate
		if !updated {
			if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
				updated = true
			}
		}

		if updated {
			if err := r.saveRemote(ctx, path, rule.GetHttp().GetUrl()); err != nil {
				return nil, fmt.Errorf("save remote failed: %w", err)
			}
		}

	case config.RemoteRule_File_case:
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

func (r *routeParser) saveRemote(ctx context.Context, path, url string) error {
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

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)

	resp, err := hc.Do(req)
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

func parseLine(txt string) (*Uri, unique.Handle[config.ModeEnum], error) {
	before := TrimComment(txt)

	uri, args, ok := SplitHostArgs(before)
	if !ok {
		return nil, unique.Handle[config.ModeEnum]{}, fmt.Errorf("split host failed: %s", txt)
	}

	modeEnum, ok := SplitModeArgs(args)
	if !ok {
		return nil, unique.Handle[config.ModeEnum]{}, fmt.Errorf("split mode failed: %s", txt)
	}

	return uri, modeEnum, nil
}

func migrateConfig(db chore.DB) {
	// migrate old config
	{
		lists := map[string]*config.List{}
		var rules []*config.Rulev2

		err := db.Batch(func(s *config.Setting) error {
			if len(s.GetBypass().GetRulesV2()) > 0 || len(s.GetBypass().GetLists()) > 0 || len(s.GetBypass().GetCustomRuleV3()) == 0 {
				return nil
			}

			for index, rule := range s.GetBypass().GetCustomRuleV3() {
				namePrefix := ""
				if rule.GetTag() == "" {
					namePrefix = fmt.Sprintf("%s_%d", rule.GetMode().String(), index)
				} else {
					namePrefix = fmt.Sprintf("%s_%d", rule.GetTag(), index)
				}

				listNames := map[string]bool{}

				for _, hostname := range rule.GetHostname() {
					data := getScheme(hostname)
					switch data.Scheme() {
					default:
						name := fmt.Sprintf("%s_host", namePrefix)
						listNames[name] = false

						list := lists[name]
						if list == nil || list.GetLocal() == nil {
							list = config.List_builder{
								ListType: config.List_host.Enum(),
								Name:     proto.String(name),
								Local:    &config.ListLocal{},
							}.Build()
							lists[name] = list
						}

						list.GetLocal().SetLists(append(list.GetLocal().GetLists(), data.Data()))

					case "process":
						name := fmt.Sprintf("%s_process", namePrefix)
						listNames[name] = true

						list := lists[name]
						if list == nil || list.GetLocal() == nil {
							list = config.List_builder{
								ListType: config.List_process.Enum(),
								Name:     proto.String(name),
								Local:    &config.ListLocal{},
							}.Build()
							lists[name] = list
						}

						list.GetLocal().SetLists(append(list.GetLocal().GetLists(), data.Data()))
					case "file", "http", "https":
						name := fmt.Sprintf("%s_remote", namePrefix)
						listNames[name] = false

						list := lists[name]
						if list == nil || list.GetRemote() == nil {
							list = config.List_builder{
								ListType: config.List_host.Enum(),
								Name:     proto.String(name),
								Remote:   &config.ListRemote{},
							}.Build()
							lists[name] = list
						}

						list.GetRemote().SetUrls(append(list.GetRemote().GetUrls(), data.Data()))
					}
				}

				or := []*config.Or{}
				for name, process := range listNames {
					if process {
						or = append(or, config.Or_builder{
							Rules: []*config.Rule{
								config.Rule_builder{
									Process: config.Process_builder{
										List: proto.String(name),
									}.Build(),
								}.Build(),
							},
						}.Build())
					} else {
						or = append(or, config.Or_builder{
							Rules: []*config.Rule{
								config.Rule_builder{
									Host: config.Host_builder{
										List: proto.String(name),
									}.Build(),
								}.Build(),
							},
						}.Build())
					}
				}

				rules = append(rules, config.Rulev2_builder{
					Name:                 proto.String(namePrefix),
					Mode:                 rule.GetMode().Enum(),
					Tag:                  proto.String(rule.GetTag()),
					ResolveStrategy:      rule.GetResolveStrategy().Enum(),
					UdpProxyFqdnStrategy: rule.GetUdpProxyFqdnStrategy().Enum(),
					Resolver:             proto.String(rule.GetResolver()),
					Rules:                or,
				}.Build())
			}

			s.GetBypass().SetLists(lists)
			s.GetBypass().SetRulesV2(rules)

			return nil
		})
		if err != nil {
			log.Error("migrate old config failed", "err", err)
		}
	}
}
