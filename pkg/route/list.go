package route

import (
	"bufio"
	"context"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/chore"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/maxminddb"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Address struct {
	name string
	m    *trie.Trie[struct{}]
}

func NewAddress(name string, hosts ...string) *Address {
	a := &Address{
		name: name,
		m:    trie.NewTrie[struct{}](),
	}

	for _, host := range hosts {
		a.m.Insert(host, struct{}{})
	}

	return a
}

func (s *Address) Add(hosts ...string) {
	for _, host := range hosts {
		s.m.Insert(host, struct{}{})
	}
}

func (s *Address) Match(ctx context.Context, addr netapi.Address) bool {
	store := netapi.GetContext(ctx)
	_, ok := s.m.Search(ctx, addr)
	store.AddMatchHistory(s.name, ok)
	return ok
}

type Process struct {
	name  string
	store *set.Set[string]
}

func NewProcess(name string, processes ...string) *Process {
	p := &Process{
		name:  name,
		store: set.NewSet[string](),
	}

	for _, process := range processes {
		p.store.Push(process)
	}

	return p
}

func (s *Process) Add(processes ...string) {
	for _, process := range processes {
		s.store.Push(process)
	}
}

func (s *Process) Match(ctx context.Context, addr netapi.Address) bool {
	store := netapi.GetContext(ctx)
	process := store.GetProcessName()
	if process != "" {
		ok := s.store.Has(process)
		store.AddMatchHistory(s.name, ok)
		return ok
	}

	store.AddMatchHistory(s.name, false)
	return false
}

type listEntry struct {
	name    string
	matcher Matcher
}

type geoip struct {
	m *maxminddb.MaxMindDB
}

type Lists struct {
	api.UnimplementedListsServer
	proxy *atomicx.Value[netapi.Proxy]

	db      chore.DB
	entries syncmap.SyncMap[string, *listEntry]

	geoip   *geoip
	geoipmu sync.RWMutex

	downloader *Downloader
	refreshing atomic.Bool

	tickermu sync.RWMutex
	ticker   *time.Timer
}

func NewLists(db chore.DB) *Lists {
	l := &Lists{
		db:    db,
		proxy: atomicx.NewValue(direct.Default),
	}

	l.downloader = &Downloader{
		path: filepath.Join(db.Dir(), "rules"),
		list: l,
	}

	interval, err := l.RefreshInterval(context.Background(), &emptypb.Empty{})
	if err != nil {
		log.Error("get refresh interval failed", "err", err)
	}

	l.resetRefreshInterval(interval.GetRefreshInterval())

	return l
}

func (s *Lists) LoadGeoip() *maxminddb.MaxMindDB {
	s.geoipmu.RLock()
	g := s.geoip
	s.geoipmu.RUnlock()

	if g != nil {
		return g.m
	}

	s.geoipmu.Lock()
	defer s.geoipmu.Unlock()

	if s.geoip != nil {
		return s.geoip.m
	}

	s.geoip = &geoip{}

	var downloadUrl string
	err := s.db.View(func(ss *config.Setting) error {
		downloadUrl = ss.GetBypass().GetMaxminddbGeoip().GetDownloadUrl()
		return nil
	})
	if err != nil {
		log.Error("get maxminddb geoip download url failed", "err", err)
		return nil
	}

	path := s.downloader.GetPath(downloadUrl)
	if path == "" {
		return nil
	}

	now := time.Now()
	ggeoip, err := maxminddb.NewMaxMindDB(path)
	if err != nil {
		log.Error("new maxminddb failed", "err", err)
		return nil
	}

	slog.Info("new geoip", "path", path, "cost", time.Since(now))

	s.geoip = &geoip{m: ggeoip}

	return ggeoip
}

func (s *Lists) List(ctx context.Context, empty *emptypb.Empty) (*api.ListResponse, error) {
	var names []string
	var maxminddbGeoip *config.MaxminddbGeoip
	err := s.db.View(func(ss *config.Setting) error {
		names = slices.Collect(maps.Keys(ss.GetBypass().GetLists()))
		maxminddbGeoip = ss.GetBypass().GetMaxminddbGeoip()
		return nil
	})

	if maxminddbGeoip == nil {
		maxminddbGeoip = config.DefaultSetting("").GetBypass().GetMaxminddbGeoip()
	}

	return api.ListResponse_builder{
		Names:          names,
		MaxminddbGeoip: maxminddbGeoip,
	}.Build(), err
}

func (s *Lists) Get(ctx context.Context, req *wrapperspb.StringValue) (*config.List, error) {
	var list *config.List
	err := s.db.View(func(ss *config.Setting) error {
		if ss.GetBypass().GetLists() != nil {
			list = ss.GetBypass().GetLists()[req.Value]
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if list == nil {
		return nil, fmt.Errorf("list %s not found", req.Value)
	}

	return list, nil
}

func (s *Lists) Save(ctx context.Context, list *config.List) (*emptypb.Empty, error) {
	// for prevent deadlock
	ctx = context.WithValue(ctx, listsRequestKey{}, true)

	list.SetErrorMsgs(list.GetErrorMsgs()[:0])

	if list.WhichList() == config.List_Remote_case {
		for _, v := range list.GetRemote().GetUrls() {
			if er := s.downloader.DownloadIfNotExists(ctx, v); er != nil {
				list.SetErrorMsgs(append(list.GetErrorMsgs(), fmt.Sprintf("%s: %s", v, er.Error())))
				log.Error("get remote failed", "err", er, "url", v)
			}
		}
	}

	er := s.db.Batch(func(ss *config.Setting) error {
		if ss.GetBypass().GetLists() == nil {
			ss.GetBypass().SetLists(map[string]*config.List{})
		}

		s.entries.Delete(list.GetName())
		ss.GetBypass().GetLists()[list.GetName()] = list
		return nil
	})
	if er != nil {
		return nil, er
	}

	return &emptypb.Empty{}, nil
}

func (s *Lists) resetRefreshInterval(minute uint64) {
	s.tickermu.Lock()
	defer s.tickermu.Unlock()

	if s.ticker != nil {
		s.ticker.Stop()
		s.ticker = nil
		log.Info("stop lists refresh ticker")
	}

	if minute == 0 {
		return
	}

	interval := time.Minute * time.Duration(minute)

	log.Info("start lists refresh ticker", "interval", interval)

	s.ticker = time.AfterFunc(interval, func() {
		_, err := s.Refresh(context.Background(), &emptypb.Empty{})
		if err != nil {
			log.Error("refresh lists failed", "err", err)
		}

		s.tickermu.Lock()
		s.ticker.Reset(interval)
		s.tickermu.Unlock()
	})
}

type listsRequestKey struct{}

func (s *Lists) refreshGeoip(ctx context.Context, download string) string {
	er := s.downloader.Download(ctx, download, func() {
		s.geoipmu.Lock()
		geoip := s.geoip
		if geoip != nil && geoip.m != nil {
			if err := geoip.m.Close(); err != nil {
				log.Error("failed to close geoip", "err", err)
			}
		}
		s.geoipmu.Unlock()
	})
	if er != nil {
		log.Error("get remote failed", "err", er, "url", download)
		return er.Error()
	}

	return ""
}

func (s *Lists) Close() error {
	s.tickermu.Lock()
	if s.ticker != nil {
		s.ticker.Stop()
		s.ticker = nil
		log.Info("stop lists refresh ticker")
	}
	s.tickermu.Unlock()

	s.geoipmu.Lock()
	geoip := s.geoip
	if geoip != nil && geoip.m != nil {
		if err := geoip.m.Close(); err != nil {
			log.Error("failed to close geoip", "err", err)
		}
	}
	s.geoipmu.Unlock()
	return nil
}

func (s *Lists) Refresh(ctx context.Context, empty *emptypb.Empty) (*emptypb.Empty, error) {
	if !s.refreshing.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("refreshing")
	}
	defer s.refreshing.Store(false)

	ctx = context.WithValue(ctx, listsRequestKey{}, true)

	errors := map[string][]string{}
	var geoipErr string

	err := s.db.View(func(ss *config.Setting) error {
		for _, v := range ss.GetBypass().GetLists() {
			if v.WhichList() != config.List_Remote_case {
				continue
			}

			errors[v.GetName()] = []string{}
			for _, url := range v.GetRemote().GetUrls() {
				er := s.downloader.Download(ctx, url, nil)
				if er != nil {
					errors[v.GetName()] = append(errors[v.GetName()], fmt.Sprintf("%s: %s", url, er.Error()))
					log.Error("download remote failed", "err", er, "url", url)
				}
			}
		}

		if ss.GetBypass().GetMaxminddbGeoip() == nil {
			ss.GetBypass().SetMaxminddbGeoip(config.DefaultSetting("").GetBypass().GetMaxminddbGeoip())
		}

		geoipErr = s.refreshGeoip(ctx, ss.GetBypass().GetMaxminddbGeoip().GetDownloadUrl())
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = s.db.Batch(func(ss *config.Setting) error {
		for k, v := range errors {
			s.entries.Delete(k)
			if ss.GetBypass().GetLists() != nil && ss.GetBypass().GetLists()[k] != nil {
				ss.GetBypass().GetLists()[k].SetErrorMsgs(v)
			}

			if ss.GetBypass().GetMaxminddbGeoip() == nil {
				ss.GetBypass().SetMaxminddbGeoip(config.DefaultSetting("").GetBypass().GetMaxminddbGeoip())
			}

			ss.GetBypass().GetMaxminddbGeoip().SetError(geoipErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (s *Lists) Remove(ctx context.Context, req *wrapperspb.StringValue) (*emptypb.Empty, error) {
	err := s.db.Batch(func(ss *config.Setting) error {
		s.entries.Delete(req.Value)
		if ss.GetBypass().GetLists() != nil {
			delete(ss.GetBypass().GetLists(), req.Value)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (s *Lists) RefreshInterval(ctx context.Context, empty *emptypb.Empty) (*api.RefreshIntervalResponse, error) {
	ret := &api.RefreshIntervalResponse{}
	err := s.db.View(func(ss *config.Setting) error {
		ret.SetRefreshInterval(ss.GetBypass().GetRefreshInterval())
		return nil
	})
	return ret, err
}

func (s *Lists) SaveRefreshInterval(ctx context.Context, req *api.RefreshIntervalResponse) (*emptypb.Empty, error) {
	err := s.db.Batch(func(ss *config.Setting) error {
		if ss.GetBypass() == nil {
			ss.SetBypass(&config.BypassConfig{})
		}

		ss.GetBypass().SetRefreshInterval(req.GetRefreshInterval())
		return nil
	})

	if err == nil {
		s.resetRefreshInterval(req.GetRefreshInterval())
	}

	return &emptypb.Empty{}, err
}

func (s *Lists) SaveMaxminddbGeoip(ctx context.Context, req *config.MaxminddbGeoip) (*emptypb.Empty, error) {
	err := s.db.Batch(func(ss *config.Setting) error {
		if ss.GetBypass() == nil {
			ss.SetBypass(&config.BypassConfig{})
		}

		ss.GetBypass().SetMaxminddbGeoip(req)

		geoipErr := s.refreshGeoip(ctx, ss.GetBypass().GetMaxminddbGeoip().GetDownloadUrl())
		ss.GetBypass().GetMaxminddbGeoip().SetError(geoipErr)
		return nil
	})
	return &emptypb.Empty{}, err
}

func (s *Lists) SetProxy(proxy netapi.Proxy) { s.proxy.Store(proxy) }

func (s *Lists) Match(ctx context.Context, name string, addr netapi.Address) bool {
	r, ok, err := s.entries.LoadOrCreate(name, func() (*listEntry, error) {
		if ctx.Value(listsRequestKey{}) == true {
			return nil, fmt.Errorf("lists is being updated")
		}

		var rules *config.List

		err := s.db.View(func(ss *config.Setting) error {
			if ss.GetBypass() != nil {
				rules = ss.GetBypass().GetLists()[name]
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		if rules == nil {
			return nil, fmt.Errorf("list %s not found", name)
		}

		var matcher Matcher
		switch rules.WhichList() {
		case config.List_Local_case:
			switch rules.GetListType() {
			case config.List_hosts_as_host:
				mc := NewAddress(rules.GetName())
				for v := range trimRuleIter(slices.Values(rules.GetLocal().GetLists())) {
					fields := strings.Fields(v)
					if len(fields) < 2 {
						continue
					}

					mc.Add(fields[1:]...)
				}
				matcher = mc
			case config.List_host:
				matcher = NewAddress(rules.GetName(), slices.Collect(trimRuleIter(slices.Values(rules.GetLocal().GetLists())))...)
			case config.List_process:
				matcher = NewProcess(rules.GetName(), slices.Collect(trimRuleIter(slices.Values(rules.GetLocal().GetLists())))...)
			default:
				return nil, fmt.Errorf("list %s is unknown", name)
			}

		case config.List_Remote_case:
			switch rules.GetListType() {
			case config.List_hosts_as_host:
				mc := NewAddress(rules.GetName())

				for v := range s.getLocalCacheTrimRuleIter(rules.GetRemote().GetUrls()) {
					/*
						example:
							::1 localhost ip6-localhost ip6-loopback
							127.0.0.1 localhost localhost.localdomain localhost4 localhost4.localdomain4
					*/
					fields := strings.Fields(v)
					if len(fields) < 2 {
						continue
					}

					mc.Add(fields[1:]...)
				}
				matcher = mc

			case config.List_host:
				mc := NewAddress(rules.GetName())

				for v := range s.getLocalCacheTrimRuleIter(rules.GetRemote().GetUrls()) {
					mc.Add(v)
				}

				matcher = mc
			case config.List_process:
				mc := NewProcess(rules.GetName())

				for v := range s.getLocalCacheTrimRuleIter(rules.GetRemote().GetUrls()) {
					mc.Add(v)
				}

				matcher = mc

			default:
				return nil, fmt.Errorf("list %s is unknown", name)
			}
		default:
			return nil, fmt.Errorf("list %s is unknown", name)
		}

		return &listEntry{
			name:    name,
			matcher: matcher,
		}, nil
	})
	if err != nil {
		log.Error("load list failed", "err", err)
		return false
	}

	if !ok {
		return false
	}

	return r.matcher.Match(ctx, addr)
}

type ListsMatcher struct {
	listName []string
	lists    *Lists
}

func NewListsMatcher(lists *Lists, listName ...string) *ListsMatcher {
	return &ListsMatcher{
		listName: listName,
		lists:    lists,
	}
}

func (s *ListsMatcher) Match(ctx context.Context, addr netapi.Address) bool {
	for _, v := range s.listName {
		if s.lists.Match(ctx, v, addr) {
			return true
		}
	}

	return false
}

func trimRule(str string) string {
	if i := strings.IndexByte(str, '#'); i != -1 {
		str = str[:i]
	}

	return strings.TrimSpace(str)
}

func trimRuleIter(strs iter.Seq[string]) iter.Seq[string] {
	return func(yield func(string) bool) {

		for v := range strs {
			if v = trimRule(v); v == "" {
				continue
			}

			if !yield(v) {
				break
			}
		}
	}
}

func ScannerIter(scanner *bufio.Scanner) iter.Seq[string] {
	return func(yield func(string) bool) {
		for scanner.Scan() {
			if !yield(scanner.Text()) {
				break
			}
		}
	}
}

func (l *Lists) getLocalCacheTrimRuleIter(rules []string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for _, v := range rules {
			r, er := l.downloader.GetReader(v)
			if er != nil {
				log.Error("get local cache failed", "err", er, "url", v)
				continue
			}
			defer r.Close()

			for str := range trimRuleIter(ScannerIter(bufio.NewScanner(r))) {
				if !yield(str) {
					return
				}
			}
		}
	}
}
