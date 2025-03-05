//go:build linux

package nftables

import (
	"bytes"
	"encoding/binary"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

var TABLENAME = "yuhaiin"

var Table = &nftables.Table{
	Name:   TABLENAME,
	Family: nftables.TableFamilyINet,
}

var Chain = &nftables.Chain{
	Name:     "output",
	Table:    Table,
	Type:     nftables.ChainTypeFilter,
	Hooknum:  nftables.ChainHookOutput,
	Priority: nftables.ChainPriorityFilter,
}

type Nftables struct {
	conn *nftables.Conn
}

func New() (*Nftables, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}

	return &Nftables{
		conn: conn,
	}, nil
}

func (n *Nftables) IsSkipMarkExist(chain *nftables.Chain, mark uint32, dev string) (*nftables.Rule, bool, error) {
	markBytes := binary.LittleEndian.AppendUint32(nil, mark)

	rules, err := n.conn.GetRules(chain.Table, chain)
	if err != nil {
		return nil, false, err
	}

	for _, r := range rules {
		if len(r.Exprs) < 5 {
			continue
		}

		meta, ok := r.Exprs[0].(*expr.Meta)
		if !ok {
			continue
		}

		if meta.Key != expr.MetaKeyMARK {
			continue
		}

		mark, ok := r.Exprs[1].(*expr.Cmp)
		if !ok {
			continue
		}

		if !bytes.Equal(mark.Data, markBytes) {
			continue
		}

		meta, ok = r.Exprs[2].(*expr.Meta)
		if !ok {
			continue
		}

		if meta.Key != expr.MetaKeyOIFNAME {
			continue
		}

		devexpr, ok := r.Exprs[3].(*expr.Cmp)
		if !ok {
			continue
		}

		if !bytes.Equal(devexpr.Data, append([]byte(string(dev)), 0)) {
			continue
		}

		return r, true, nil
	}

	return nil, false, nil
}

func (n *Nftables) DeleteSkipMark(chain *nftables.Chain, mark uint32, dev string) error {
	rule, exist, err := n.IsSkipMarkExist(chain, mark, dev)
	if err != nil {
		return err
	}

	if !exist {
		return nil
	}

	if err = n.conn.DelRule(rule); err != nil {
		return err
	}

	return n.conn.Flush()
}

func (n *Nftables) AddSkipMark(chain *nftables.Chain, mark uint32, dev string) error {
	_, exist, err := n.IsSkipMarkExist(chain, mark, dev)
	if err != nil {
		return err
	}

	if exist {
		return nil
	}

	exprs := []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyMARK,
			Register: uint32(0x1),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: uint32(0x1),
			Data:     binary.LittleEndian.AppendUint32(nil, mark),
		},
		&expr.Meta{
			Key:      expr.MetaKeyOIFNAME,
			Register: uint32(0x1),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: uint32(0x1),
			Data:     append([]byte(string(dev)), 0),
		},
		&expr.Counter{},
		// &expr.Verdict{
		// 	Kind: expr.VerdictDrop,
		// },
		&expr.Reject{
			Type: unix.NFT_REJECT_ICMP_UNREACH,
			// Network Unreachable  0
			// Host Unreachable     1
			// Protocol Unreachable 2
			// Port Unreachable     3
			Code: 0,
		},
	}

	n.conn.AddRule(&nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: exprs,
	})
	return n.conn.Flush()
}

func (n *Nftables) CreateTable(table *nftables.Table) error {
	n.conn.CreateTable(table)
	return n.conn.Flush()
}

func (n *Nftables) CreateChain(chain *nftables.Chain) error {
	n.conn.AddChain(chain)
	return n.conn.Flush()
}

func (n *Nftables) ListRules(chain *nftables.Chain) ([]*nftables.Rule, error) {
	return n.conn.GetRules(chain.Table, chain)
}

func (n *Nftables) TableExist(name string) (bool, error) {
	tbs, err := n.conn.ListTables()
	if err != nil {
		return false, err
	}

	for _, v := range tbs {
		if v.Name == name {
			return true, nil
		}
	}

	return false, nil

}

func (n *Nftables) ChainExist(table, chain string) (bool, error) {
	cs, err := n.conn.ListChains()
	if err != nil {
		return false, err
	}

	for _, v := range cs {
		if v.Table.Name == table && v.Name == chain {
			return true, nil
		}
	}

	return false, nil
}

func (n *Nftables) DeleteTable(table *nftables.Table) error {
	n.conn.DelTable(table)
	return n.conn.Flush()
}
