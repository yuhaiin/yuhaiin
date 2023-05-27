package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	nd "github.com/Asutorufa/yuhaiin/pkg/net/dns"
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Setting interface {
	gc.ConfigDaoServer
	AddObserver(Observer)
}

type Observer interface {
	Update(*config.Setting)
}

type ObserverFunc func(*config.Setting)

func (o ObserverFunc) Update(s *config.Setting) { o(s) }

type setting struct {
	gc.UnimplementedConfigDaoServer
	current *config.Setting
	path    string

	os []Observer

	mu sync.RWMutex
}

func NewConfig(path string) Setting {
	data, err := os.ReadFile(path)
	data = SetDefault(data, defaultConfig(path))

	if err != nil {
		log.Error("read config file failed", "err", err)
		os.WriteFile(path, data, os.ModePerm)
	}

	var pa config.Setting
	err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, &pa)
	if err != nil {
		log.Error("unmarshal config file failed", "err", err)
	}

	return &setting{current: &pa, path: path}
}

func (c *setting) Load(context.Context, *emptypb.Empty) (*config.Setting, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current, nil
}

func (c *setting) Save(_ context.Context, s *config.Setting) (*emptypb.Empty, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	err := save(s, c.path)
	if err != nil {
		return &emptypb.Empty{}, fmt.Errorf("save settings failed: %w", err)
	}

	c.current = proto.Clone(s).(*config.Setting)

	wg := sync.WaitGroup{}
	for i := range c.os {
		wg.Add(1)
		go func(o Observer) {
			defer wg.Done()
			o.Update(proto.Clone(c.current).(*config.Setting))
		}(c.os[i])
	}
	wg.Wait()

	return &emptypb.Empty{}, nil
}

func (c *setting) AddObserver(o Observer) {
	if o == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.os = append(c.os, o)
	o.Update(c.current)
}

func save(pa *config.Setting, dir string) error {
	_, err := os.Stat(dir)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(filepath.Dir(dir), os.ModePerm)
		if err != nil {
			return fmt.Errorf("make dir failed: %w", err)
		}
	}

	if err = check(pa); err != nil {
		return err
	}

	data, err := protojson.MarshalOptions{Multiline: true, Indent: "\t", EmitUnpopulated: true}.Marshal(pa)
	if err != nil {
		return fmt.Errorf("marshal setting failed: %w", err)
	}

	return os.WriteFile(dir, data, os.ModePerm)
}

func check(pa *config.Setting) error {
	err := CheckBootstrapDns(pa.Dns.Bootstrap)
	if err != nil {
		return err
	}

	return nil
}

func CheckBootstrapDns(pa *pd.Dns) error {
	addr, err := nd.ParseAddr(0, pa.Host, "443")
	if err != nil {
		return err
	}

	if addr.Type() != proxy.IP {
		return fmt.Errorf("dns bootstrap host is only support ip address")
	}

	return nil
}
