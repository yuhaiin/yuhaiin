package route

import (
	"bufio"
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/list"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Address struct {
	m *trie.Trie[struct{}]
}

func NewAddress(hosts ...string) *Address {
	a := &Address{
		m: trie.NewTrie[struct{}](),
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
	_, ok := s.m.Search(ctx, addr)
	return ok
}

type Process struct {
	store *list.Set[string]
}

func NewProcess(processes ...string) *Process {
	p := &Process{
		store: list.NewSet[string](),
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
	process := netapi.GetContext(ctx).GetProcessName()
	if process != "" {
		return s.store.Has(process)
	}

	return false
}

type listEntry struct {
	name    string
	matcher Matcher
}

type Lists struct {
	mu      sync.RWMutex
	db      config.DB
	lists   map[string]*bypass.List
	entries syncmap.SyncMap[string, *listEntry]
	proxy   netapi.Proxy
	gc.UnimplementedListsServer
}

func NewLists(db config.DB) *Lists {
	l := &Lists{
		db:    db,
		proxy: direct.Default,
	}
	err := db.View(func(s *config.Setting) error {
		l.lists = s.GetBypass().GetLists()
		return nil
	})
	if err != nil {
		log.Error("load lists failed", "err", err)
	}

	if l.lists == nil {
		l.lists = make(map[string]*bypass.List)
	}

	return l
}

func (s *Lists) List(ctx context.Context, empty *emptypb.Empty) (*gc.ListResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return gc.ListResponse_builder{
		Names: slices.Collect(maps.Keys(s.lists)),
	}.Build(), nil
}

func (s *Lists) Get(ctx context.Context, req *wrapperspb.StringValue) (*bypass.List, error) {
	s.mu.RLock()
	l := s.lists[req.Value]
	s.mu.RUnlock()

	return l, nil
}

func (s *Lists) Save(ctx context.Context, list *bypass.List) (*emptypb.Empty, error) {
	ctx = context.WithValue(ctx, listsRequestKey{}, true)

	s.mu.Lock()
	list.SetErrorMsgs(list.GetErrorMsgs()[:0])

	if list.WhichList() == bypass.List_Remote_case {
		for _, v := range list.GetRemote().GetUrls() {
			_, er := getRemote(ctx, filepath.Join(s.db.Dir(), "rules"), s.proxy, v, false)
			if er != nil {
				list.SetErrorMsgs(append(list.GetErrorMsgs(), fmt.Sprintf("%s: %s", v, er.Error())))
				log.Error("get remote failed", "err", er, "url", v)
			}
		}
	}

	s.lists[list.GetName()] = list
	s.entries.Delete(list.GetName())

	er := s.db.Batch(func(ss *config.Setting) error {
		ss.GetBypass().SetLists(s.lists)
		return nil
	})
	if er != nil {
		s.mu.Unlock()
		return nil, er
	}

	s.mu.Unlock()

	return &emptypb.Empty{}, nil
}

type listsRequestKey struct{}

func (s *Lists) Refresh(ctx context.Context, empty *emptypb.Empty) (*emptypb.Empty, error) {
	ctx = context.WithValue(ctx, listsRequestKey{}, true)

	errors := map[string][]string{}

	s.mu.RLock()

	for _, v := range s.lists {
		if v.WhichList() == bypass.List_Remote_case {
			errors[v.GetName()] = []string{}
			for _, url := range v.GetRemote().GetUrls() {
				_, er := getRemote(ctx, filepath.Join(s.db.Dir(), "rules"),
					s.proxy, url, true)
				if er != nil {
					errors[v.GetName()] = append(errors[v.GetName()], fmt.Sprintf("%s: %s", url, er.Error()))
					log.Error("get remote failed", "err", er, "url", url)
				}
			}

		}
	}
	s.mu.RUnlock()

	s.mu.Lock()
	for k, v := range errors {
		s.entries.Delete(k)
		if list := s.lists[k]; list != nil {
			list.SetErrorMsgs(v)
		}
	}
	s.mu.Unlock()

	err := s.db.Batch(func(ss *config.Setting) error {
		ss.GetBypass().SetLists(s.lists)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (s *Lists) Remove(ctx context.Context, req *wrapperspb.StringValue) (*emptypb.Empty, error) {
	s.mu.Lock()

	delete(s.lists, req.Value)
	s.entries.Delete(req.Value)
	err := s.db.Batch(func(ss *config.Setting) error {
		ss.GetBypass().SetLists(s.lists)
		return nil
	})
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}

	s.mu.Unlock()

	return &emptypb.Empty{}, nil
}

func (s *Lists) SetProxy(proxy netapi.Proxy) {
	s.mu.Lock()
	s.proxy = proxy
	s.mu.Unlock()
}

func (s *Lists) Match(ctx context.Context, name string, addr netapi.Address) bool {
	r, ok, err := s.entries.LoadOrCreate(name, func() (*listEntry, error) {
		if ctx.Value(listsRequestKey{}) == true {
			return nil, fmt.Errorf("lists is being updated")
		}

		s.mu.RLock()
		rules, ok := s.lists[name]
		s.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("list %s not found", name)
		}

		var matcher Matcher
		switch rules.WhichList() {
		case bypass.List_Local_case:
			switch rules.GetListType() {
			case bypass.List_host:
				matcher = NewAddress(rules.GetLocal().GetLists()...)
			case bypass.List_process:
				matcher = NewProcess(rules.GetLocal().GetLists()...)
			default:
				return nil, fmt.Errorf("list %s is unknown", name)
			}

		case bypass.List_Remote_case:

			switch rules.GetListType() {
			case bypass.List_host:
				mc := NewAddress()

				for _, v := range rules.GetRemote().GetUrls() {
					r, er := getLocalCache(filepath.Join(s.db.Dir(), "rules"), v)
					if er != nil {
						log.Error("get local cache failed", "err", er, "url", v)
						continue
					}

					scanner := bufio.NewScanner(r)
					for scanner.Scan() {
						mc.Add(scanner.Text())
					}
				}

				matcher = mc
			case bypass.List_process:
				mc := NewProcess()

				for _, v := range rules.GetRemote().GetUrls() {
					r, er := getLocalCache(filepath.Join(s.db.Dir(), "rules"), v)
					if er != nil {
						log.Error("get local cache failed", "err", er, "url", v)
						continue
					}

					scanner := bufio.NewScanner(r)
					for scanner.Scan() {
						mc.Add(scanner.Text())
					}
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
	listName string
	lists    *Lists
}

func NewListsMatcher(lists *Lists, listName string) *ListsMatcher {
	return &ListsMatcher{
		listName: listName,
		lists:    lists,
	}
}

func (s *ListsMatcher) Match(ctx context.Context, addr netapi.Address) bool {
	return s.lists.Match(ctx, s.listName, addr)
}
