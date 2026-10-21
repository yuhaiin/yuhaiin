package route

import (
	"context"
	"crypto/sha256"
	json "encoding/json/v2"
	"fmt"
	"slices"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/maxminddb"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type preparedLists struct {
	names        map[string]string
	listIssues   []contractroute.ListActivationIssue
	unavailable  map[string]bool
	host         *hostMatcher
	process      *processMatcher
	fingerprint  [32]byte
	disk         bool
	geo          *maxminddb.MaxMindDB
	geoChanged   bool
	geoURL       string
	geoRefreshed uint64
}

// prepareRules builds indexes before changing the running configuration. Rule
// compilation only consumes list IDs; all data/index work stays in Lists.
func (s *Lists) prepareRules(ctx context.Context, rules []contractroute.RouteRule) (*preparedLists, error) {
	var refreshed uint64
	if s.settings != nil {
		settings, err := s.settings.ListSettings(ctx)
		if err != nil {
			return nil, err
		}
		refreshed = settings.LastRefreshTime
	}
	return s.prepareRuleData(ctx, rules, func(id string) (contractroute.RouteListDetail, error) {
		if s.lists == nil {
			return contractroute.RouteListDetail{}, fmt.Errorf("list %q is unavailable", id)
		}
		return s.lists.GetRouteList(ctx, id)
	}, s.hostTrieDisk.Load(), refreshed)
}

func (s *Lists) prepareSnapshot(ctx context.Context, snapshot plainstore.RouteSnapshot) (*preparedLists, error) {
	lists := make(map[string]contractroute.RouteListDetail, len(snapshot.Lists))
	for _, list := range snapshot.Lists {
		lists[list.ID] = list
	}
	rules := make([]contractroute.RouteRule, 0, len(snapshot.Rules))
	for _, entry := range snapshot.Rules {
		rules = append(rules, entry.Rule)
	}
	prepared, err := s.prepareRuleData(ctx, rules, func(id string) (contractroute.RouteListDetail, error) {
		if list, ok := lists[id]; ok {
			return list, nil
		}
		return contractroute.RouteListDetail{}, fmt.Errorf("list %q is unavailable", id)
	}, snapshot.ListSettings.HostIndexDisk, snapshot.ListSettings.LastRefreshTime)
	if err != nil {
		return nil, err
	}
	settings := snapshot.ListSettings
	s.geoipmu.RLock()
	changed := s.geoipURL != settings.MaxMindDBDownloadURL || s.geoipRefreshed != settings.LastRefreshTime
	s.geoipmu.RUnlock()
	if !changed {
		return prepared, nil
	}
	if prepared == nil {
		prepared = &preparedLists{}
	}
	prepared.geoChanged = true
	prepared.geoURL = settings.MaxMindDBDownloadURL
	prepared.geoRefreshed = settings.LastRefreshTime
	if prepared.geoURL != "" {
		if err := s.downloader.DownloadIfNotExists(ctx, prepared.geoURL, nil); err != nil {
			prepared.close()
			return nil, err
		}
		geo, err := maxminddb.NewMaxMindDB(s.downloader.GetPath(prepared.geoURL))
		if err != nil {
			prepared.close()
			return nil, fmt.Errorf("prepare GeoIP: %w", err)
		}
		prepared.geo = geo
	}
	return prepared, nil
}

func (s *Lists) prepareRuleData(ctx context.Context, rules []contractroute.RouteRule, get func(string) (contractroute.RouteListDetail, error), disk bool, refreshed uint64) (*preparedLists, error) {
	refs := map[string]string{}
	for _, rule := range rules {
		if rule.Disabled {
			continue
		}
		if err := contractroute.VisitListRefs(rule.Rules, func(kind, id string) error {
			if previous, exists := refs[id]; exists && previous != kind {
				return fmt.Errorf("list %q is used as both host and process data", id)
			}
			refs[id] = kind
			return nil
		}); err != nil {
			return nil, err
		}
	}
	ids := make([]string, 0, len(refs))
	for id := range refs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	type matchingData struct {
		ID, Type string
		Source   contractroute.ListSource
	}
	names := make(map[string]string, len(ids))
	data := make([]matchingData, 0, len(ids))
	for _, id := range ids {
		list, err := get(id)
		if err != nil {
			return nil, err
		}
		if refs[id] == "process" && list.Type != "process" || refs[id] == "host" && list.Type != "host" && list.Type != "hosts_as_host" {
			return nil, fmt.Errorf("list %q has incompatible type %q", list.Name, list.Type)
		}
		names[id] = list.Name
		data = append(data, matchingData{ID: id, Type: list.Type, Source: list.Source})
	}
	// Validate remote resources independently. A broken subscription must not
	// prevent unrelated rules from becoming active. Only readable cached files
	// contribute to the index; failed sources remain visible in runtime status.
	unavailable := make(map[string]bool)
	issues := make([]contractroute.ListActivationIssue, 0)
	for i := range data {
		item := &data[i]
		if item.Source.Type != "remote" {
			continue
		}
		var urls []string
		if item.Source.Remote != nil {
			urls = item.Source.Remote.URLs
		}
		valid := make([]string, 0, len(urls))
		problems := make([]string, 0)
		for _, url := range urls {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			fetchErr := s.downloader.DownloadIfNotExists(ctx, url, nil)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			reader, readErr := s.downloader.GetReader(url)
			if readErr == nil {
				_ = reader.Close()
				valid = append(valid, url)
			}
			if fetchErr != nil || readErr != nil {
				problem := fmt.Sprintf("%s: %v", url, fetchErr)
				if fetchErr == nil {
					problem = fmt.Sprintf("%s: %v", url, readErr)
				} else if readErr == nil {
					problem += " (using cached file)"
				}
				problems = append(problems, problem)
			}
		}
		if len(urls) == 0 {
			problems = append(problems, "no remote URLs configured")
		}
		if len(valid) == 0 {
			unavailable[item.ID] = true
		}
		if len(problems) > 0 {
			message := strings.Join(problems, "; ")
			if len(message) > 512 {
				message = message[:512]
			}
			issues = append(issues, contractroute.ListActivationIssue{
				ID: item.ID, Name: names[item.ID], Error: message, Unavailable: unavailable[item.ID],
			})
			log.Warn("route list source unavailable during apply", "list", item.ID, "error", message, "unavailable", unavailable[item.ID])
		}
		// Do not silently fold an unavailable remote source into an empty
		// match set; the entire referencing rule is skipped during compilation.
		item.Source.Remote = &contractroute.RemoteSource{URLs: valid}
	}
	encoded, err := json.Marshal(struct {
		Data      []matchingData
		Disk      bool
		Refreshed uint64
	}{data, disk, refreshed})
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(encoded)
	if fingerprint == s.indexFingerprint {
		return &preparedLists{names: names, listIssues: issues, unavailable: unavailable}, nil
	}
	prepared := &preparedLists{names: names, listIssues: issues, unavailable: unavailable, host: newHostTrie(configuration.DataDir.Load(), disk), process: newProcessTrie(), fingerprint: fingerprint, disk: disk}
	success := false
	defer func() {
		if !success {
			_ = prepared.host.Close()
		}
	}()
	for _, item := range data {
		if unavailable[item.ID] {
			continue
		}
		values, err := s.values(contractroute.RouteListDetail{ID: item.ID, Type: item.Type, Source: item.Source})
		if err != nil {
			return nil, err
		}
		if item.Type == "process" {
			for value := range values {
				if value = strings.TrimSpace(value); value != "" {
					prepared.process.Add(value, item.ID)
				}
			}
		} else if err := prepared.host.Add(values, item.ID); err != nil {
			return nil, err
		}
	}
	if err := prepared.host.Optimize(); err != nil {
		return nil, err
	}
	if err := prepared.host.Sync(); err != nil {
		return nil, err
	}
	success = true
	return prepared, nil
}

func (p *preparedLists) close() {
	if p.host != nil {
		_ = p.host.Close()
	}
	if p.geo != nil {
		_ = p.geo.Close()
	}
}

func (s *Lists) installPrepared(prepared *preparedLists) {
	s.hostTrieRefreshVersion.Add(1)
	s.hostTrieRefreshTimerMu.Lock()
	if s.hostTrieRefreshTimer != nil {
		s.hostTrieRefreshTimer.Stop()
	}
	s.hostTrieRefreshTimerMu.Unlock()
	s.hostTrieRefreshAt.Store(0)
	if prepared == nil {
		return
	}
	if prepared.geoChanged {
		s.geoipmu.Lock()
		old := s.geoip
		s.geoip = &struct{ m *maxminddb.MaxMindDB }{prepared.geo}
		s.geoipURL, s.geoipRefreshed = prepared.geoURL, prepared.geoRefreshed
		if old != nil && old.m != nil {
			_ = old.m.Close()
		}
		s.geoipmu.Unlock()
	}
	if prepared.host == nil {
		return
	}
	s.hostListMu.Lock()
	defer s.hostListMu.Unlock()
	s.hostTrieMu.Lock()
	old := s.hostTrie
	s.hostTrie = prepared.host
	s.hostTrieMu.Unlock()
	s.processTrieMu.Lock()
	s.processTrie = prepared.process
	s.processTrieMu.Unlock()
	s.indexFingerprint = prepared.fingerprint
	s.hostTrieDisk.Store(prepared.disk)
	if old != nil {
		_ = old.Close()
	}
}
