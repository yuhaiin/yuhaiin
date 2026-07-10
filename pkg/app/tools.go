package app

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/licenses"
	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
)

type Tools struct {
	logController *log.Controller
}

func NewTools(logController *log.Controller) *Tools {
	return &Tools{logController: logController}
}

func (t *Tools) Interfaces(context.Context) (contracttools.Interfaces, error) {
	var out contracttools.Interfaces
	iis, err := interfaces.GetInterfaceList()
	if err != nil {
		return contracttools.Interfaces{}, err
	}
	for _, i := range iis {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		iface := contracttools.Interface{Name: i.Name}
		addresses, err := i.Addrs()
		if err == nil {
			for _, a := range addresses {
				iface.Addresses = append(iface.Addresses, a.String())
			}
		}
		out.Interfaces = append(out.Interfaces, iface)
	}
	return out, nil
}

func (t *Tools) Licenses(context.Context) (contracttools.Licenses, error) {
	toLicenses := func(ls []licenses.License) []contracttools.License {
		var ret []contracttools.License
		for _, l := range ls {
			ret = append(ret, contracttools.License{
				Name:       l.Name,
				URL:        l.URL,
				License:    l.License,
				LicenseURL: l.LicenseURL,
			})
		}
		return ret
	}
	return contracttools.Licenses{
		Yuhaiin: toLicenses(licenses.Yuhaiin()),
		Android: toLicenses(licenses.Android()),
	}, nil
}

func (t *Tools) TailLogs(ctx context.Context, send func(contracttools.LogBatch) error) error {
	return t.logController.Tail(ctx, func(line []string) error {
		return send(contracttools.LogBatch{Log: line})
	})
}
