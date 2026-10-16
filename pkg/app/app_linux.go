//go:build !android

package app

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/nftables"
)

func init() {
	operators = append(operators, func(c *closers) {
		c.AddCloser("nftables", &nftablesClear{})
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
