package control

import (
	"context"
	"errors"

	schemaapi "github.com/Asutorufa/yuhaiin/pkg/schema/api"
)

type Runtime interface {
	BuildInfo(ctx context.Context) (*schemaapi.RuntimeInfo, error)
}

type RuntimeAdapter struct {
	Config ConfigPort
}

func (p RuntimeAdapter) BuildInfo(ctx context.Context) (*schemaapi.RuntimeInfo, error) {
	if p.Config == nil {
		return nil, errors.New("runtime config service is nil")
	}

	info, err := p.Config.Info(ctx, &schemaapi.Empty{})
	if err != nil {
		return nil, err
	}

	return &schemaapi.RuntimeInfo{
		Version:   info.GetVersion(),
		Commit:    info.GetCommit(),
		BuildTime: info.GetBuildTime(),
		GoVersion: info.GetGoVersion(),
		Platform:  info.GetPlatform(),
		Compiler:  info.GetCompiler(),
		Arch:      info.GetArch(),
		OS:        info.GetOs(),
		Build:     info.GetBuild_(),
	}, nil
}
