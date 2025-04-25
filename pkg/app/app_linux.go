//go:build !android

package app

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/nftables"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/server"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tproxy"
)

func init() {
	operators = append(operators, func(c *closers) {
		c.AddCloser("nftables", &nftablesClear{})
		c.AddCloser("bpf_tcplife", netlink.BpfCloser())
	})
}

type nftablesClear struct{}

func (n *nftablesClear) Close() error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}

	return nft.DeleteTable(nftables.Table)
}
