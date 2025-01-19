package openvpn

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/ooni/minivpn/pkg/config"
	"github.com/ooni/minivpn/pkg/tunnel"
)

type OpenVPN struct {
}

func NewOpenVPN(ss []byte) {
	op, err := config.ReadConfigFile("")
	if err != nil {
		panic(err)
	}

	json.NewEncoder(os.Stdout).Encode(op)

	cf := config.NewConfig(
		config.WithOpenVPNOptions(op),
	)

	tt, err := tunnel.Start(context.TODO(), &net.Dialer{}, cf)
	if err != nil {
		panic(err)
	}

	s, err := CreateNetTUN(1500, tt)
	if err != nil {
		panic(err)
	}

	dialer := NewDialer(s)

	hc := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				add, err := net.ResolveTCPAddr(network, addr)
				if err != nil {
					return nil, err
				}
				return dialer.DialContextTCP(ctx, add)
			},
		},
	}

	resp, err := hc.Get("https://1.1.1.1")
	if err != nil {
		panic(err)
	}
	resp.Body.Close()

	_, err = io.Copy(os.Stdout, resp.Body)
	if err != nil {
		panic(err)
	}
}
