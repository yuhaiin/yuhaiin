package tools

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/components/config"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Tools struct {
	tools.UnimplementedToolsServer
	setting config.Setting
	dialer  netapi.Proxy
}

func NewTools(dialer netapi.Proxy, setting config.Setting) *Tools {
	return &Tools{
		setting: setting,
		dialer:  dialer,
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

	f, err := os.OpenFile(st.Bypass.BypassFile, os.O_CREATE|os.O_RDWR, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	_, err = relay.Copy(f, resp.Body)
	return &emptypb.Empty{}, err
}