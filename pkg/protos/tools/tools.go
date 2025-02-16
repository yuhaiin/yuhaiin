package tools

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/licenses"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Tools struct {
	UnimplementedToolsServer
	db config.DB
}

func NewTools(db config.DB) *Tools {
	return &Tools{db: db}
}

func (t *Tools) GetInterface(ctx context.Context, e *emptypb.Empty) (*Interfaces, error) {
	androidApp := false
	_ = t.db.View(func(s *config.Setting) error {
		androidApp = s.GetPlatform().GetAndroidApp()
		return nil
	})
	if androidApp {
		return &Interfaces{}, nil
	}

	is := &Interfaces_builder{}
	iis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range iis {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		iif := &Interface_builder{
			Name: &i.Name,
		}

		addresses, err := i.Addrs()
		if err == nil {
			for _, a := range addresses {
				iif.Addresses = append(iif.Addresses, a.String())
			}
		}
		is.Interfaces = append(is.Interfaces, iif.Build())
	}

	return is.Build(), nil
}

func (t *Tools) Licenses(context.Context, *emptypb.Empty) (*Licenses, error) {
	toLicenses := func(ls []licenses.License) []*License {
		var ret []*License
		for _, l := range ls {
			ret = append(ret, License_builder{
				Name:       proto.String(l.Name),
				Url:        proto.String(l.URL),
				License:    proto.String(l.License),
				LicenseUrl: proto.String(l.LicenseURL),
			}.Build())
		}
		return ret
	}

	return Licenses_builder{
		Yuhaiin: toLicenses(licenses.Yuhaiin()),
		Android: toLicenses(licenses.Android()),
	}.Build(), nil
}
