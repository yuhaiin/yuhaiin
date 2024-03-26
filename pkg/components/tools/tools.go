package tools

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/components/config"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Tools struct {
	tools.UnimplementedToolsServer
	setting  config.Setting
	dialer   netapi.Proxy
	callback func(*pc.Setting)
}

func NewTools(dialer netapi.Proxy, setting config.Setting, callback func(st *pc.Setting)) *Tools {
	return &Tools{
		setting:  setting,
		dialer:   dialer,
		callback: callback,
	}
}

func (t *Tools) SaveRemoteBypassFile(ctx context.Context, url *wrapperspb.StringValue) (*emptypb.Empty, error) {
	http := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				add, err := netapi.ParseAddress(netapi.PaseNetwork(network), addr)
				if err != nil {
					return nil, err
				}
				return t.dialer.Conn(ctx, add)
			},
		},
	}

	st, err := t.setting.Load(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(st.Bypass.BypassFile), os.ModeDir); err != nil {
		return nil, err
	}

	resp, err := http.Get(url.Value)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(st.Bypass.BypassFile, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return nil, err
	}

	_, err = relay.Copy(f, resp.Body)
	_ = f.Close()

	if err == nil {
		t.callback(st)
	}

	return &emptypb.Empty{}, err
}

func (t *Tools) GetInterface(context.Context, *emptypb.Empty) (*tools.Interfaces, error) {
	is := &tools.Interfaces{}
	iis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range iis {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		iif := &tools.Interface{
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
