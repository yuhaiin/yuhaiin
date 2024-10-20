package tools

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/config"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Tools struct {
	UnimplementedToolsServer
	db config.Setting
}

func NewTools(db config.Setting) *Tools {
	return &Tools{db: db}
}

func (t *Tools) GetInterface(ctx context.Context, e *emptypb.Empty) (*Interfaces, error) {
	if cf, err := t.db.Load(ctx, e); err == nil && cf.Platform.AndroidApp {
		return &Interfaces{}, nil
	}

	is := &Interfaces{}
	iis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range iis {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		iif := &Interface{
			Name: i.Name,
		}

		addresses, err := i.Addrs()
		if err == nil {
			for _, a := range addresses {
				iif.Addresses = append(iif.Addresses, a.String())
			}
		}
		is.Interfaces = append(is.Interfaces, iif)
	}

	return is, nil
}
