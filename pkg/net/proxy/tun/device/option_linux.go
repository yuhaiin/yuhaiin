//go:build !android

package device

import (
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nftables"
)

func (o *Opt) SkipMark() {
	if err := o.skipMark(); err != nil {
		log.Warn("skip mark failed", "err", err)
	}
}

func (o *Opt) skipMark() error {
	if o.Interface.Name == "" {
		return nil
	}

	nft, err := nftables.New()
	if err != nil {
		return err
	}

	ok, _ := nft.TableExist(nftables.Table.Name)
	if !ok {
		if err := nft.CreateTable(nftables.Table); err != nil {
			return err
		}
	}

	ok, _ = nft.ChainExist(nftables.Table.Name, nftables.Chain.Name)
	if !ok {
		if err := nft.CreateChain(nftables.Chain); err != nil {
			return err
		}
	}

	return nft.AddSkipMark(nftables.Chain, uint32(Mark), o.Interface.Name)
}

func (o *Opt) UnSkipMark() {
	nft, err := nftables.New()
	if err != nil {
		log.Warn("un skip mark failed", "err", err)
		return
	}

	if err := nft.DeleteTable(nftables.Table); err != nil {
		log.Warn("un skip mark failed", "err", err)
	}
}
