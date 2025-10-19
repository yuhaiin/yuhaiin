package chore

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/licenses"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	tools "github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	grpc "google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Tools struct {
	api.UnimplementedToolsServer
	db            DB
	logController *log.Controller
}

func NewTools(db DB, logController *log.Controller) *Tools {
	return &Tools{db: db, logController: logController}
}

func (t *Tools) GetInterface(ctx context.Context, e *emptypb.Empty) (*tools.Interfaces, error) {
	is := &tools.Interfaces_builder{}
	iis, err := interfaces.GetInterfaceList()
	if err != nil {
		return nil, err
	}
	for _, i := range iis {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		iif := &tools.Interface_builder{
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

func (t *Tools) Licenses(context.Context, *emptypb.Empty) (*tools.Licenses, error) {
	toLicenses := func(ls []licenses.License) []*tools.License {
		var ret []*tools.License
		for _, l := range ls {
			ret = append(ret, tools.License_builder{
				Name:       proto.String(l.Name),
				Url:        proto.String(l.URL),
				License:    proto.String(l.License),
				LicenseUrl: proto.String(l.LicenseURL),
			}.Build())
		}
		return ret
	}

	return tools.Licenses_builder{
		Yuhaiin: toLicenses(licenses.Yuhaiin()),
		Android: toLicenses(licenses.Android()),
	}.Build(), nil
}

func (t *Tools) Log(_ *emptypb.Empty, stream grpc.ServerStreamingServer[tools.Log]) error {
	return t.logController.Tail(stream.Context(), func(line []string) {
		for _, l := range line {
			if err := stream.Send(tools.Log_builder{
				Log: proto.String(l),
			}.Build()); err != nil {
				return
			}
		}
	})
}

func (t *Tools) Logv2(empty *emptypb.Empty, v2 grpc.ServerStreamingServer[tools.Logv2]) error {
	return t.logController.Tail(v2.Context(), func(line []string) {
		if err := v2.Send(tools.Logv2_builder{
			Log: line,
		}.Build()); err != nil {
			return
		}
	})
}
