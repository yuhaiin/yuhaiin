//go:build linux

package hysteria2

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type hopRedirect struct {
	conn  *nftables.Conn
	table *nftables.Table
	once  sync.Once
	err   error
}

func newHopRedirect(address net.Addr, value string) (io.Closer, error) {
	ports, err := parseHopPorts(value)
	if err != nil {
		return nil, err
	}
	addr, ok := address.(*net.UDPAddr)
	if !ok || addr.Port == 0 {
		return nil, fmt.Errorf("hysteria2 port hopping requires a bound UDP listener, got %v", address)
	}
	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}
	// A stable, listener-specific table replaces this listener's stale rules
	// after a crash. Other listeners and unrelated firewall tables are retained.
	id := sha256.Sum256([]byte(address.String()))
	table := &nftables.Table{Name: fmt.Sprintf("yuhaiin_hy2_%x", id[:8]), Family: nftables.TableFamilyINet}
	tables, err := conn.ListTablesOfFamily(table.Family)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 hopping needs nftables and CAP_NET_ADMIN: %w", err)
	}
	for _, existing := range tables {
		if existing.Name == table.Name {
			conn.DelTable(existing)
		}
	}
	conn.CreateTable(table)
	for _, hook := range []struct {
		name string
		hook *nftables.ChainHook
	}{
		{"prerouting", nftables.ChainHookPrerouting},
		{"output", nftables.ChainHookOutput},
	} {
		chain := conn.AddChain(&nftables.Chain{Name: hook.name, Table: table, Type: nftables.ChainTypeNAT, Hooknum: hook.hook, Priority: nftables.ChainPriorityNATDest})
		families := []uint32{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6}
		if addr.IP.To4() != nil {
			families = families[:1]
		} else if !addr.IP.IsUnspecified() {
			families = families[1:]
		}
		for _, family := range families {
			for _, ports := range ports {
				expressions := hopDestinationExpressions(addr, family)
				expressions = append(expressions,
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
					&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: binary.BigEndian.AppendUint16(nil, ports.Start), ToData: binary.BigEndian.AppendUint16(nil, ports.End)},
					&expr.Immediate{Register: 1, Data: binary.BigEndian.AppendUint16(nil, uint16(addr.Port))},
					// Port-only DNAT preserves the destination IP, including explicitly
					// bound addresses and localhost. Conntrack restores the hop port
					// on replies. No userspace UDP forwarding is involved.
					&expr.NAT{Type: expr.NATTypeDestNAT, Family: family, RegProtoMin: 1},
				)
				conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: expressions})
			}
		}
	}
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("hysteria2 install hopping rules (requires nftables and CAP_NET_ADMIN): %w", err)
	}
	return &hopRedirect{conn: conn, table: table}, nil
}

func hopDestinationExpressions(addr *net.UDPAddr, family uint32) []expr.Any {
	expressions := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(family)}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
	}
	if addr.IP.IsUnspecified() {
		return append(expressions,
			&expr.Fib{Register: 1, FlagDADDR: true, ResultADDRTYPE: true},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.NativeEndian.AppendUint32(nil, unix.RTN_LOCAL)},
		)
	}
	offset, ip := uint32(24), addr.IP.To16()
	if family == unix.NFPROTO_IPV4 {
		offset, ip = 16, addr.IP.To4()
	}
	return append(expressions,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(ip))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip},
	)
}

func (r *hopRedirect) Close() error {
	r.once.Do(func() {
		r.conn.DelTable(r.table)
		r.err = r.conn.Flush()
	})
	return r.err
}
