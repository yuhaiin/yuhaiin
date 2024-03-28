package config

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Setting interface {
	gc.ConfigServiceServer
	AddObserver(Observer)
}

type Observer interface {
	Update(*config.Setting)
}

type ObserverFunc func(*config.Setting)

func (o ObserverFunc) Update(s *config.Setting) { o(s) }

type setting struct {
	gc.UnimplementedConfigServiceServer

	db *jsondb.DB[*config.Setting]

	os []Observer

	mu sync.RWMutex
}

func NewConfig(path string) Setting {
	return &setting{db: jsondb.Open(path, defaultSetting(path))}
}

func (c *setting) Info(context.Context, *emptypb.Empty) (*config.Info, error) { return Info(), nil }

func Info() *config.Info {
	var build []string
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, v := range info.Settings {
			build = append(build, fmt.Sprintf("%s=%s", v.Key, v.Value))
		}
	}

	return &config.Info{
		Version:   version.Version,
		Commit:    version.GitCommit,
		BuildTime: version.BuildTime,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		Compiler:  runtime.Compiler,
		Arch:      runtime.GOARCH,
		Os:        runtime.GOOS,
		Build:     build,
	}
}

func (c *setting) Load(context.Context, *emptypb.Empty) (*config.Setting, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.db.Data, nil
}

func (c *setting) Save(_ context.Context, s *config.Setting) (*emptypb.Empty, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.db.Data = proto.Clone(s).(*config.Setting)
	if err := c.db.Save(); err != nil {
		return &emptypb.Empty{}, fmt.Errorf("save settings failed: %w", err)
	}

	wg := sync.WaitGroup{}
	for i := range c.os {
		wg.Add(1)
		go func(o Observer) {
			defer wg.Done()
			o.Update(proto.Clone(c.db.Data).(*config.Setting))
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
	o.Update(c.db.Data)
}
