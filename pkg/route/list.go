package route

import (
	"bufio"
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/list"
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
	if ok {
		store.AddMatchHistory(fmt.Sprintf("host/%s/yes", s.name))
	} else {
		store.AddMatchHistory(fmt.Sprintf("host/%s/no", s.name))
	}
	return ok
}

type Process struct {
	name  string
	store *list.Set[string]
}

func NewProcess(name string, processes ...string) *Process {
	p := &Process{
		name:  name,
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
	store := netapi.GetContext(ctx)
	process := store.GetProcessName()
	if process != "" {
		ok := s.store.Has(process)
		if ok {
			store.AddMatchHistory(fmt.Sprintf("process/%s/yes", s.name))
		} else {
			store.AddMatchHistory(fmt.Sprintf("process/%s/no", s.name))
		}
		return ok
	} else {
		store.AddMatchHistory("process/empty")
	}

	return false
}

type listEntry struct {
	name    string
	matcher Matcher
}

type Lists struct {
	db      config.DB
	entries syncmap.SyncMap[string, *listEntry]
	proxy   *atomicx.Value[netapi.Proxy]
	gc.UnimplementedListsServer
}

func NewLists(db config.DB) *Lists {
	l := &Lists{
		db:    db,
		proxy: atomicx.NewValue(direct.Default),
	}

	return l
}

func (s *Lists) List(ctx context.Context, empty *emptypb.Empty) (*gc.ListResponse, error) {
	var names []string
	err := s.db.View(func(ss *config.Setting) error {
		names = slices.Collect(maps.Keys(ss.GetBypass().GetLists()))
		return nil
	})

	return gc.ListResponse_builder{
		Names: names,
	}.Build(), err
}

func (s *Lists) Get(ctx context.Context, req *wrapperspb.StringValue) (*bypass.List, error) {
	var list *bypass.List
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

func (s *Lists) Save(ctx context.Context, list *bypass.List) (*emptypb.Empty, error) {
	ctx = context.WithValue(ctx, listsRequestKey{}, true)

	list.SetErrorMsgs(list.GetErrorMsgs()[:0])

	if list.WhichList() == bypass.List_Remote_case {
		for _, v := range list.GetRemote().GetUrls() {
			_, er := getRemote(ctx, filepath.Join(s.db.Dir(), "rules"), s.proxy.Load(), v, false)
			if er != nil {
				list.SetErrorMsgs(append(list.GetErrorMsgs(), fmt.Sprintf("%s: %s", v, er.Error())))
				log.Error("get remote failed", "err", er, "url", v)
			}
		}
	}

	er := s.db.Batch(func(ss *config.Setting) error {
		if ss.GetBypass().GetLists() == nil {
			ss.GetBypass().SetLists(map[string]*bypass.List{})
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

type listsRequestKey struct{}

func (s *Lists) Refresh(ctx context.Context, empty *emptypb.Empty) (*emptypb.Empty, error) {
	ctx = context.WithValue(ctx, listsRequestKey{}, true)

	errors := map[string][]string{}

	err := s.db.View(func(ss *config.Setting) error {
		for _, v := range ss.GetBypass().GetLists() {
			if v.WhichList() == bypass.List_Remote_case {
				errors[v.GetName()] = []string{}
				for _, url := range v.GetRemote().GetUrls() {
					_, er := getRemote(ctx, filepath.Join(s.db.Dir(), "rules"),
						s.proxy.Load(), url, true)
					if er != nil {
						errors[v.GetName()] = append(errors[v.GetName()], fmt.Sprintf("%s: %s", url, er.Error()))
						log.Error("get remote failed", "err", er, "url", url)
					}
				}

			}
		}

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

func (s *Lists) SetProxy(proxy netapi.Proxy) { s.proxy.Store(proxy) }

func (s *Lists) Match(ctx context.Context, name string, addr netapi.Address) bool {
	r, ok, err := s.entries.LoadOrCreate(name, func() (*listEntry, error) {
		if ctx.Value(listsRequestKey{}) == true {
			return nil, fmt.Errorf("lists is being updated")
		}

		var rules *bypass.List

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
		case bypass.List_Local_case:
			switch rules.GetListType() {
			case bypass.List_host:
				matcher = NewAddress(rules.GetName(), rules.GetLocal().GetLists()...)
			case bypass.List_process:
				matcher = NewProcess(rules.GetName(), rules.GetLocal().GetLists()...)
			default:
				return nil, fmt.Errorf("list %s is unknown", name)
			}

		case bypass.List_Remote_case:

			switch rules.GetListType() {
			case bypass.List_host:
				mc := NewAddress(rules.GetName())

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
				mc := NewProcess(rules.GetName())

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
