package route

import (
	"bufio"
	"context"
	"fmt"
	"iter"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cache/pebble"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/maxminddb"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/codec"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type Cache interface {
	Dir() string
	Close() error
}
type hostMatcher struct {
	lists *set.Set[string]
	trie  *trie.Trie[string]
	cache Cache
	mu    sync.Mutex
}

func newHostTrie(path string) *hostMatcher {
	path, err := os.MkdirTemp(path, "trie.*.db")
	if err != nil {
		// mkdirtemp will try over 10000 times
		// if failed, it must be something wrong, so we just panic
		panic(err)
	}

	pebble, err := pebble.New(path)
	if err != nil {
		log.Error("new pebble failed", "err", err)
	}

	trie := trie.NewTrie(trie.WithPebble(pebble), trie.WithCodec(codec.UnsafeStringCodec{}))

	return &hostMatcher{
		lists: set.NewSet[string](),
		trie:  trie,
		cache: pebble,
	}
}

func (h *hostMatcher) Clear() {
	h.lists.Clear()
	if err := h.trie.Clear(); err != nil {
		log.Error("clear host matcher trie failed", "err", err)
	}
}

func (h *hostMatcher) Close() error {
	_ = h.trie.Close()
	if h.cache == nil {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	defer os.RemoveAll(h.cache.Dir())
	err := h.cache.Close()
	h.cache = nil
	return err
}

func (h *hostMatcher) Add(host iter.Seq[string], list string) {
	h.lists.Push(list)
	err := h.trie.Batch(func(yield func(string, string) bool) {
		for str := range host {
			if !yield(str, list) {
				return
			}
		}
	})
	if err != nil {
		log.Error("add host failed", "err", err)
	}
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

	if slices.Contains(*set, list) {
		return
	}

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

func (h *processMatcher) Empty() bool {
	for range h.trie.Range {
		return false
	}

	return true
}

type Lists struct {
	lists    RouteListBook
	settings RouteListSettingsBook

	proxy *atomicx.Value[netapi.Proxy]

	geoip *struct {
		m *maxminddb.MaxMindDB
	}

	downloader *Downloader

	ticker *time.Timer

	hostTrie               *hostMatcher
	hostTrieRefreshTimer   *time.Timer
	hostTrieRefreshTimerMu sync.Mutex
	hostTrieRefreshMu      sync.Mutex
	hostTrieRefreshAt      atomic.Int64
	hostTrieRefreshVersion atomic.Uint64

	processTrie *processMatcher

	geoipmu sync.RWMutex

	tickermu sync.RWMutex

	hostTrieMu sync.RWMutex

	processTrieMu sync.RWMutex

	refreshing atomic.Bool
}

type RouteListBook interface {
	ListRouteListDetails(context.Context) ([]contractroute.RouteListDetail, error)
	GetRouteList(context.Context, string) (contractroute.RouteListDetail, error)
	SaveRouteList(context.Context, contractroute.RouteListDetail, int64) error
}

type RouteListSettingsBook interface {
	ListSettings(context.Context) (RouteListSettings, error)
	SaveListSettings(context.Context, RouteListSettings) error
}

type RouteListSettings = plainstore.RouteListSettings

func NewLists(lists RouteListBook, settings RouteListSettingsBook, configPath string) *Lists {
	// remove orphan trie db
	files, err := filepath.Glob(filepath.Join(configuration.DataDir.Load(), "trie.*.db"))
	if err == nil {
		for _, f := range files {
			if err := os.RemoveAll(f); err != nil {
				log.Warn("remove old trie db failed", "path", f, "err", err)
			}
		}
	}

	proxy := atomicx.NewValue(direct.Default)

	l := &Lists{
		lists:       lists,
		settings:    settings,
		proxy:       proxy,
		downloader:  NewDownloader(filepath.Join(configPath, "rules"), proxy.Load),
		hostTrie:    newHostTrie(configuration.DataDir.Load()),
		processTrie: newProcessTrie(),
	}

	l.hostTrieRefreshTimer = time.AfterFunc(time.Second, l.refreshHostTrieAndMarkApplied)

	var interval uint64
	if settings != nil {
		if config, err := settings.ListSettings(context.Background()); err == nil {
			interval = config.RefreshInterval
		}
	}

	l.resetRefreshInterval(interval)

	return l
}

func (s *Lists) notifyRefreshHostTrie() {
	s.hostTrieRefreshVersion.Add(1)
	s.hostTrieRefreshAt.Store(time.Now().Add(time.Minute).UnixMilli())
	s.hostTrieRefreshTimerMu.Lock()
	s.hostTrieRefreshTimer.Reset(time.Minute)
	s.hostTrieRefreshTimerMu.Unlock()
}

func (s *Lists) refreshHostTrieAndMarkApplied() {
	s.hostTrieRefreshMu.Lock()
	defer s.hostTrieRefreshMu.Unlock()
	version := s.hostTrieRefreshVersion.Load()
	s.refreshHostTrie()
	if s.hostTrieRefreshVersion.Load() == version {
		s.hostTrieRefreshAt.Store(0)
	}
}

func (s *Lists) ApplyListChangesNow() {
	s.hostTrieRefreshVersion.Add(1)
	s.hostTrieRefreshTimerMu.Lock()
	if s.hostTrieRefreshTimer != nil {
		s.hostTrieRefreshTimer.Stop()
	}
	s.hostTrieRefreshTimerMu.Unlock()
	s.refreshHostTrieAndMarkApplied()
}

func (s *Lists) ApplyListChanges() {
	s.refreshProcessTrie()
	s.notifyRefreshHostTrie()
}

func (s *Lists) ActivationStatus() contractroute.ListActivationStatus {
	return contractroute.ListActivationStatus{HostIndexRefreshAt: s.hostTrieRefreshAt.Load()}
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
	if s.settings == nil {
		return nil
	}
	settings, err := s.settings.ListSettings(context.Background())
	if err != nil {
		log.Error("get maxminddb geoip download url failed", "err", err)
		return nil
	}
	downloadUrl = settings.MaxMindDBDownloadURL

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

	if minute > uint64(math.MaxInt64/int64(time.Minute)) {
		log.Warn("route list refresh interval exceeds time.Duration range", "min", minute)
		return
	}

	interval := time.Minute * time.Duration(minute)

	log.Info("start lists refresh ticker", "interval", interval, "min", minute)

	s.ticker = time.AfterFunc(interval, func() {
		if err := s.RefreshContract(context.Background()); err != nil {
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
	return s.hostTrie.Close()
}

func (s *Lists) RefreshContract(ctx context.Context) error {
	if !s.refreshing.CompareAndSwap(false, true) {
		return fmt.Errorf("refreshing")
	}
	defer s.refreshing.Store(false)

	if s.lists == nil || s.settings == nil {
		return nil
	}

	lists, err := s.lists.ListRouteListDetails(ctx)
	if err != nil {
		return err
	}
	settings, err := s.settings.ListSettings(ctx)
	if err != nil {
		return err
	}

	errorMsgs := map[string][]string{}
	for _, list := range lists {
		if list.Source.Type != "remote" || list.Source.Remote == nil {
			continue
		}
		errorMsgs[list.Name] = make([]string, 0, len(list.Source.Remote.URLs))
		for _, url := range list.Source.Remote.URLs {
			ctx, cancel := context.WithTimeout(ctx, time.Minute*3/2)
			er := s.downloader.Download(ctx, url, nil)
			cancel()
			if er != nil {
				errorMsgs[list.Name] = append(errorMsgs[list.Name], fmt.Sprintf("%s: %s", url, er.Error()))
				log.Error("download remote failed", "err", er, "url", url)
			}
		}
	}

	for _, list := range lists {
		if nextErrors, ok := errorMsgs[list.Name]; ok {
			list.ErrorMsgs = nextErrors
			if err := s.lists.SaveRouteList(ctx, list, 0); err != nil {
				return err
			}
		}
	}

	settings.MaxMindDBError = s.refreshGeoip(ctx, settings.MaxMindDBDownloadURL, true)
	settings.LastRefreshTime = uint64(time.Now().Unix())
	settings.Error = ""
	if err := s.settings.SaveListSettings(ctx, settings); err != nil {
		return err
	}

	s.notifyRefreshHostTrie()
	s.refreshProcessTrie()
	return nil
}

func (s *Lists) SaveContractConfig(ctx context.Context, req contractroute.ListConfig, refreshInterval uint64) error {
	if s.settings == nil {
		return nil
	}
	settings, err := s.settings.ListSettings(ctx)
	if err != nil {
		return err
	}
	if refreshInterval != settings.RefreshInterval {
		s.resetRefreshInterval(refreshInterval)
	}
	settings.RefreshInterval = refreshInterval
	settings.MaxMindDBDownloadURL = req.MaxMindDBGeoIP.DownloadURL
	settings.MaxMindDBError = s.refreshGeoip(ctx, settings.MaxMindDBDownloadURL, false)
	settings.Error = ""
	err = s.settings.SaveListSettings(ctx, settings)
	return err
}

func (s *Lists) SetProxy(proxy netapi.Proxy) { s.proxy.Store(proxy) }

func (s *Lists) getIter(name string) (contractroute.RouteListDetail, iter.Seq[string], error) {
	if s.lists == nil {
		return contractroute.RouteListDetail{}, nil, fmt.Errorf("route list store is unavailable")
	}
	rules, err := s.lists.GetRouteList(context.Background(), name)
	if err != nil {
		return contractroute.RouteListDetail{}, nil, err
	}

	var iter iter.Seq[string]

	switch rules.Source.Type {
	case "local", "":
		values := []string(nil)
		if rules.Source.Local != nil {
			values = rules.Source.Local.Lists
		}
		switch rules.Type {
		case "hosts_as_host":
			iter = func(yield func(string) bool) {
				for v := range trimRuleIter(slices.Values(values)) {
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
		case "host", "process":
			iter = trimRuleIter(slices.Values(values))
		default:
			return contractroute.RouteListDetail{}, nil, fmt.Errorf("list %s is unknown", name)
		}

	case "remote":
		urls := []string(nil)
		if rules.Source.Remote != nil {
			urls = rules.Source.Remote.URLs
		}
		switch rules.Type {
		case "hosts_as_host":
			iter = func(yield func(string) bool) {
				for v := range s.getLocalCacheTrimRuleIter(urls) {
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
		case "host", "process":
			iter = s.getLocalCacheTrimRuleIter(urls)
		default:
			return contractroute.RouteListDetail{}, nil, fmt.Errorf("list %s is unknown", name)
		}
	default:
		return contractroute.RouteListDetail{}, nil, fmt.Errorf("list %s is unknown", name)
	}

	return rules, iter, nil
}

func (s *Lists) refreshHostTrie() {
	hostTrie := newHostTrie(configuration.DataDir.Load())
	for name := range s.hostTrie.lists.Range {
		_, iter, err := s.getIter(name)
		if err != nil {
			log.Error("get iter failed", "err", err)
			continue
		}

		hostTrie.Add(iter, name)
	}

	s.hostTrieMu.Lock()
	if err := s.hostTrie.Close(); err != nil {
		log.Error("close host trie failed", "err", err)
	}
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
	s.hostTrie.Clear()
	s.hostTrieMu.Unlock()
}

func (s *Lists) AddNewHostList(name string) {
	rules, iter, err := s.getIter(name)
	if err != nil {
		log.Warn("get list failed", "list", name, "err", err)
		return
	}

	if rules.Type == "process" {
		return
	}

	s.hostTrieMu.Lock()
	defer s.hostTrieMu.Unlock()

	s.hostTrie.Add(iter, name)
}

func (s *Lists) refreshProcessTrie() {
	processTrie := newProcessTrie()
	for name := range s.processTrie.Range {
		if processTrie.Include(name) {
			continue
		}

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

	if rules.Type != "process" {
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
				log.Warn("get local cache failed", "err", er, "url", v)
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
