package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/app"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/migrate"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
)

func main() {
	dir, err := os.MkdirTemp("", "yuhaiin-example-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	db := migrate.NewStateDB(paths.PathGenerator.State(dir))
	instance, err := app.Start(&app.StartOptions{
		ConfigPath:    dir,
		Auth:          nil,
		ProcessDumper: nil,
		StateStore:    db,
	})
	if err != nil {
		panic(err)
	}
	defer instance.Close()

	direct, err := contractnode.NewTypedProtocol(contractnode.Direct{})
	if err != nil {
		panic(err)
	}

	pp, err := instance.Node.Save(context.TODO(), contractnode.Node{
		ID:      "example-direct",
		Group:   "test",
		Name:    "test",
		Origin:  "example",
		Enabled: true,
		Chain:   []contractnode.Protocol{direct},
	})
	if err != nil {
		panic(err)
	}

	if err := instance.Node.Use(context.TODO(), pp.ID); err != nil {
		panic(err)
	}

	c := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				add, err := netapi.ParseAddress(network, addr)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %w", err)
				}

				ctx = netapi.WithContext(ctx)

				return configuration.ProxyChain.Conn(ctx, add)
			},
		},
	}

	req, err := http.NewRequest("GET", "http://ip.sb", nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("User-Agent", "curl/8.12.1")

	resp, err := c.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	err = resp.Write(os.Stdout)
	if err != nil {
		log.Fatal(err)
	}
}
