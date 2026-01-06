package route

import (
	"bufio"
	"context"
	"fmt"
	"iter"
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
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/maxminddb"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type hostMatcher struct {
	lists *set.Set[string]
	trie  *trie.Trie[string]
}

func newHostTrie() *hostMatcher {
	return &hostMatcher{
		lists: set.NewSet[string](),
		trie:  trie.NewTrie[string](),
	}
}

func (h *hostMatcher) Add(host string, list string) {
	h.lists.Push(list)
	h.trie.Insert(host, list)
}

func (h *hostMatcher) Search(ctx context.Context, addr netapi.Address) []string {
	return h.trie.Search(ctx, addr)
}

func (h *hostMatcher) Include(list string) bool {
	return h.lists.Has(list)
}

type processMatcher struct {
	trie syncmap.SyncMap[string, *[]string]
}

func newProcessTrie() *processMatcher {
	return &processMatcher{}
}

func (h *processMatcher) Add(process string, list string) {
	set, _, _ := h.trie.LoadOrCreate(process, func() (*[]string, error) {
		return &[]string{}, nil
	})

	*set = append(*set, list)
}

func (h *processMatcher) Range(yield func(string) bool) {
	for _, v := range h.trie.Range {
		for _, v := range *v {
			if !yield(v) {
				return
			}
		}
	}
}

func (h *processMatcher) Include(list string) bool {
	for v := range h.Range {
		if v == list {
			return true
		}
	}
	return false
}

func (h *processMatcher) Search(ctx context.Context, addr netapi.Address) []string {
	store := netapi.GetContext(ctx)
	process := store.GetProcessName()
	s, ok := h.trie.Load(process)
	if !ok {
		return nil
	}
	return *s
}

type Lists struct {
	api.UnimplementedListsServer
	proxy *atomicx.Value[netapi.Proxy]

	db chore.DB

	geoip *struct {
		m *maxminddb.MaxMindDB
	}
	geoipmu sync.RWMutex

	downloader *Downloader

	tickermu sync.RWMutex
	ticker   *time.Timer

	hostTrieMu sync.RWMutex
	hostTrie   *hostMatcher

	processTrieMu sync.RWMutex
	processTrie   *processMatcher

	refreshing atomic.Bool
}

func NewLists(db chore.DB) *Lists {
	proxy := atomicx.NewValue(direct.Default)

	l := &Lists{
		db:          db,
		proxy:       proxy,
		downloader:  NewDownloader(filepath.Join(db.Dir(), "rules"), proxy.Load),
		hostTrie:    newHostTrie(),
		processTrie: newProcessTrie(),
	}

	var interval uint64
	_ = db.View(func(s *config.Setting) error {
		interval = s.GetBypass().GetRefreshConfig().GetRefreshInterval()
		return nil
	})

	l.resetRefreshInterval(interval)

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

	s.geoip = &struct{ m *maxminddb.MaxMindDB }{}

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

	log.Info("new geoip", "path", path, "cost", time.Since(now))

	s.geoip = &struct{ m *maxminddb.MaxMindDB }{m: ggeoip}

	return ggeoip
}

func (s *Lists) List(ctx context.Context, empty *emptypb.Empty) (*api.ListResponse, error) {
	ret := &api.ListResponse{}

	err := s.db.View(func(ss *config.Setting) error {
		ret.SetNames(slices.Collect(maps.Keys(ss.GetBypass().GetLists())))
		ret.SetMaxminddbGeoip(ss.GetBypass().GetMaxminddbGeoip())
		ret.SetRefreshConfig(ss.GetBypass().GetRefreshConfig())
		return nil
	})

	if ret.GetMaxminddbGeoip() == nil {
		ret.SetMaxminddbGeoip(config.DefaultSetting("").GetBypass().GetMaxminddbGeoip())
	}

	if ret.GetRefreshConfig() == nil {
		ret.SetRefreshConfig(config.RefreshConfig_builder{RefreshInterval: proto.Uint64(0)}.Build())
	}

	return ret, err
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
	list.SetErrorMsgs(list.GetErrorMsgs()[:0])

	if list.WhichList() == config.List_Remote_case {
		for _, v := range list.GetRemote().GetUrls() {
			ctx, cancel := context.WithTimeout(ctx, time.Minute*3/2)
			er := s.downloader.DownloadIfNotExists(ctx, v, nil)
			cancel()
			if er != nil {
				list.SetErrorMsgs(append(list.GetErrorMsgs(), fmt.Sprintf("%s: %s", v, er.Error())))
				log.Error("get remote failed", "err", er, "url", v)
			}
		}
	}

	er := s.db.Batch(func(ss *config.Setting) error {
		if ss.GetBypass().GetLists() == nil {
			ss.GetBypass().SetLists(map[string]*config.List{})
		}

		ss.GetBypass().GetLists()[list.GetName()] = list
		return nil
	})
	if er != nil {
		return nil, er
	}

	if s.HostTrie().Include(list.GetName()) {
		s.refreshHostTrie()
	}

	if s.ProcessTrie().Include(list.GetName()) {
		s.refreshProcessTrie()
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

	log.Info("start lists refresh ticker", "interval", interval, "min", minute)

	// overflow
	if interval <= 0 {
		return
	}

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

func (s *Lists) closeCurrentGeoip() {
	s.geoipmu.Lock()
	defer s.geoipmu.Unlock()

	geoip := s.geoip
	if geoip == nil || geoip.m == nil {
		return
	}

	if err := geoip.m.Close(); err != nil {
		log.Error("failed to close geoip", "err", err)
	}

	geoip.m = nil
}

func (s *Lists) refreshGeoip(ctx context.Context, download string, force bool) string {
	var err error
	if force {
		err = s.downloader.Download(ctx, download, s.closeCurrentGeoip)
	} else {
		err = s.downloader.DownloadIfNotExists(ctx, download, s.closeCurrentGeoip)
	}

	s.geoipmu.Lock()
	if s.geoip.m == nil {
		s.geoip = nil
	}
	s.geoipmu.Unlock()

	if err != nil {
		log.Error("get remote failed", "err", err, "url", download)
		return err.Error()
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

	s.closeCurrentGeoip()
	return nil
}

func (s *Lists) Refresh(ctx context.Context, empty *emptypb.Empty) (*emptypb.Empty, error) {
	if !s.refreshing.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("refreshing")
	}
	defer s.refreshing.Store(false)

	var lists []*config.List
	var geoipUrl string

	err := s.db.View(func(ss *config.Setting) error {
		if ss.GetBypass().GetMaxminddbGeoip() == nil {
			ss.GetBypass().SetMaxminddbGeoip(config.DefaultSetting("").GetBypass().GetMaxminddbGeoip())
		}

		lists = slices.Collect(maps.Values(ss.GetBypass().GetLists()))
		geoipUrl = ss.GetBypass().GetMaxminddbGeoip().GetDownloadUrl()

		return nil
	})
	if err != nil {
		return nil, err
	}

	errors := map[string][]string{}

	for _, v := range lists {
		if v.WhichList() != config.List_Remote_case {
			continue
		}

		errors[v.GetName()] = make([]string, 0, len(v.GetRemote().GetUrls()))

		for _, url := range v.GetRemote().GetUrls() {
			ctx, cancel := context.WithTimeout(ctx, time.Minute*3/2)
			er := s.downloader.Download(ctx, url, nil)
			cancel()
			if er != nil {
				errors[v.GetName()] = append(errors[v.GetName()], fmt.Sprintf("%s: %s", url, er.Error()))
				log.Error("download remote failed", "err", er, "url", url)
			}
		}
	}

	geoipErr := s.refreshGeoip(ctx, geoipUrl, true)

	err = s.db.Batch(func(ss *config.Setting) error {
		for k, v := range errors {
			if ss.GetBypass().GetLists() != nil && ss.GetBypass().GetLists()[k] != nil {
				ss.GetBypass().GetLists()[k].SetErrorMsgs(v)
			}
		}

		if ss.GetBypass().GetMaxminddbGeoip() == nil {
			ss.GetBypass().SetMaxminddbGeoip(config.DefaultSetting("").GetBypass().GetMaxminddbGeoip())
		}

		ss.GetBypass().GetMaxminddbGeoip().SetError(geoipErr)

		if ss.GetBypass().GetRefreshConfig() == nil {
			ss.GetBypass().SetRefreshConfig(config.RefreshConfig_builder{RefreshInterval: proto.Uint64(0)}.Build())
		}

		ss.GetBypass().GetRefreshConfig().SetLastRefreshTime(uint64(time.Now().Unix()))
		if err != nil {
			ss.GetBypass().GetRefreshConfig().SetError(err.Error())
		} else {
			ss.GetBypass().GetRefreshConfig().SetError("")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	s.refreshHostTrie()
	s.refreshProcessTrie()

	return &emptypb.Empty{}, nil
}

func (s *Lists) Remove(ctx context.Context, req *wrapperspb.StringValue) (*emptypb.Empty, error) {
	err := s.db.Batch(func(ss *config.Setting) error {
		if ss.GetBypass().GetLists() != nil {
			delete(ss.GetBypass().GetLists(), req.Value)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if s.HostTrie().Include(req.Value) {
		s.refreshHostTrie()
	}

	if s.ProcessTrie().Include(req.Value) {
		s.refreshProcessTrie()
	}

	return &emptypb.Empty{}, nil
}

func (s *Lists) SaveConfig(ctx context.Context, req *api.SaveListConfigRequest) (*emptypb.Empty, error) {
	err := s.db.Batch(func(ss *config.Setting) error {
		if ss.GetBypass() == nil {
			ss.SetBypass(&config.BypassConfig{})
		}

		ss.GetBypass().SetMaxminddbGeoip(req.GetMaxminddbGeoip())

		if ss.GetBypass().GetRefreshConfig() == nil {
			ss.GetBypass().SetRefreshConfig(&config.RefreshConfig{})
		}

		if req.GetRefreshInterval() != ss.GetBypass().GetRefreshConfig().GetRefreshInterval() {
			// the refresh run in the [time.AfterFunc], so here will not deadlock
			s.resetRefreshInterval(req.GetRefreshInterval())
		}

		ss.GetBypass().GetRefreshConfig().SetRefreshInterval(req.GetRefreshInterval())

		geoipErr := s.refreshGeoip(ctx, ss.GetBypass().GetMaxminddbGeoip().GetDownloadUrl(), false)
		ss.GetBypass().GetMaxminddbGeoip().SetError(geoipErr)
		return nil
	})

	return &emptypb.Empty{}, err
}

func (s *Lists) SetProxy(proxy netapi.Proxy) { s.proxy.Store(proxy) }

func (s *Lists) getIter(name string) (*config.List, iter.Seq[string], error) {
	var rules *config.List

	err := s.db.View(func(ss *config.Setting) error {
		if ss.GetBypass() != nil {
			rules = ss.GetBypass().GetLists()[name]
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	if rules == nil {
		return nil, nil, fmt.Errorf("list %s not found", name)
	}

	var iter iter.Seq[string]

	switch rules.WhichList() {
	case config.List_Local_case:
		switch rules.GetListType() {
		case config.List_hosts_as_host:
			iter = func(yield func(string) bool) {
				for v := range trimRuleIter(slices.Values(rules.GetLocal().GetLists())) {
					/*
						example:
							::1 localhost ip6-localhost ip6-loopback
							127.0.0.1 localhost localhost.localdomain localhost4 localhost4.localdomain4
					*/
					fields := strings.Fields(v)
					if len(fields) < 2 {
						continue
					}

					for _, v := range fields[1:] {
						if !yield(v) {
							return
						}
					}
				}
			}
		case config.List_host:
			iter = trimRuleIter(slices.Values(rules.GetLocal().GetLists()))
		case config.List_process:
			iter = trimRuleIter(slices.Values(rules.GetLocal().GetLists()))
		default:
			return nil, nil, fmt.Errorf("list %s is unknown", name)
		}

	case config.List_Remote_case:
		switch rules.GetListType() {
		case config.List_hosts_as_host:
			iter = func(yield func(string) bool) {
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

					for _, v := range fields[1:] {
						if !yield(v) {
							return
						}
					}
				}
			}
		case config.List_host:
			iter = s.getLocalCacheTrimRuleIter(rules.GetRemote().GetUrls())
		case config.List_process:
			iter = s.getLocalCacheTrimRuleIter(rules.GetRemote().GetUrls())
		default:
			return nil, nil, fmt.Errorf("list %s is unknown", name)
		}
	default:
		return nil, nil, fmt.Errorf("list %s is unknown", name)
	}

	return rules, iter, nil
}

func (s *Lists) refreshHostTrie() {
	hostTrie := newHostTrie()
	for name := range s.hostTrie.lists.Range {
		_, iter, err := s.getIter(name)
		if err != nil {
			log.Error("get iter failed", "err", err)
			continue
		}

		for v := range iter {
			hostTrie.Add(v, name)
		}
	}

	s.hostTrieMu.Lock()
	s.hostTrie = hostTrie
	s.hostTrieMu.Unlock()
}

func (s *Lists) HostTrie() *hostMatcher {
	s.hostTrieMu.RLock()
	defer s.hostTrieMu.RUnlock()
	return s.hostTrie
}

func (s *Lists) SetHostTrie(hostTrie *hostMatcher) {
	s.hostTrieMu.Lock()
	s.hostTrie = hostTrie
	s.hostTrieMu.Unlock()
}

func (s *Lists) ResetHostTrie() {
	s.hostTrieMu.Lock()
	s.hostTrie = newHostTrie()
	s.hostTrieMu.Unlock()
}

func (s *Lists) AddNewHostList(name string) {
	rules, iter, err := s.getIter(name)
	if err != nil {
		log.Warn("get list failed", "list", name, "err", err)
		return
	}

	if rules.GetListType() == config.List_process {
		return
	}

	s.hostTrieMu.Lock()
	defer s.hostTrieMu.Unlock()

	for v := range iter {
		s.hostTrie.Add(v, name)
	}
}

func (s *Lists) refreshProcessTrie() {
	processTrie := newProcessTrie()
	for name := range s.processTrie.Range {
		_, iter, err := s.getIter(name)
		if err != nil {
			log.Error("get iter failed", "err", err)
			continue
		}

		for v := range iter {
			processTrie.Add(v, name)
		}
	}

	s.processTrieMu.Lock()
	s.processTrie = processTrie
	s.processTrieMu.Unlock()
}

func (s *Lists) ProcessTrie() *processMatcher {
	s.processTrieMu.RLock()
	defer s.processTrieMu.RUnlock()
	return s.processTrie
}

func (s *Lists) SetProcessTrie(processTrie *processMatcher) {
	s.processTrieMu.Lock()
	s.processTrie = processTrie
	s.processTrieMu.Unlock()
}

func (s *Lists) ResetProcessTrie() {
	s.processTrieMu.Lock()
	s.processTrie = newProcessTrie()
	s.processTrieMu.Unlock()
}

func (s *Lists) AddNewProcessList(name string) {
	rules, iter, err := s.getIter(name)
	if err != nil {
		log.Warn("get list failed", "list", name, "err", err)
		return
	}

	if rules.GetListType() != config.List_process {
		return
	}

	s.processTrieMu.Lock()
	defer s.processTrieMu.Unlock()

	for v := range iter {
		s.processTrie.Add(v, name)
	}
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
