//go:build linux && !android

package nft

import (
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"
)

// Supported reports whether this platform has the nftables backend.
const Supported = true

func table() *nftables.Table {
	return &nftables.Table{Name: Table, Family: nftables.TableFamilyINet}
}

func ifname(name string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name+"\x00")
	return b
}

func u32(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }

func family(f string) []expr.Any {
	switch f {
	case "ip":
		return []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}}}
	case "ip6":
		return []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}}}
	}
	return nil
}

func daddr(v6 bool) *expr.Payload {
	if v6 {
		return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16}
	}
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}
}

var l4 = map[string]byte{"tcp": unix.IPPROTO_TCP, "udp": unix.IPPROTO_UDP, "icmpv6": unix.IPPROTO_ICMPV6}

func ruleExprs(r Rule, sets map[string]*nftables.Set) ([]expr.Any, error) {
	e := family(r.Family)
	v6 := r.Family == "ip6"
	if r.OifName != "" {
		e = append(e, &expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(r.OifName)})
	}
	if r.Oif != 0 {
		e = append(e, &expr.Meta{Key: expr.MetaKeyOIF, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: u32(uint32(r.Oif))})
	}
	if r.Set != "" {
		s, ok := sets[r.Set]
		if !ok {
			return nil, fmt.Errorf("unknown set %q", r.Set)
		}
		e = append(e, daddr(v6), &expr.Lookup{SourceRegister: 1, SetName: s.Name, SetID: s.ID})
	}
	if r.Daddr.IsValid() {
		length := uint32(r.Daddr.Addr().BitLen() / 8)
		mask := net.CIDRMask(r.Daddr.Bits(), r.Daddr.Addr().BitLen())
		e = append(e, daddr(v6),
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: length, Mask: mask, Xor: make([]byte, length)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: r.Daddr.Masked().Addr().AsSlice()})
	}
	if r.L4 != "" {
		op := expr.CmpOpEq
		if r.NotL4 {
			op = expr.CmpOpNeq
		}
		e = append(e, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: op, Register: 1, Data: []byte{l4[r.L4]}})
	}
	if r.ICMPType != 0 {
		e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{r.ICMPType}})
	}
	if r.Sport != 0 {
		e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, r.Sport)})
	}
	if r.Dport != 0 {
		e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, r.Dport)})
	}
	if r.Mark != 0 {
		e = append(e, &expr.Meta{Key: expr.MetaKeyMARK, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: u32(r.Mark)})
	}
	e = append(e, &expr.Counter{})
	switch {
	case r.Verdict == "accept":
		e = append(e, &expr.Verdict{Kind: expr.VerdictAccept})
	case r.Verdict == "reject" && r.RejectTCPReset:
		e = append(e, &expr.Reject{Type: unix.NFT_REJECT_TCP_RST})
	case r.Verdict == "reject":
		e = append(e, &expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED})
	default:
		return nil, fmt.Errorf("unknown verdict %q", r.Verdict)
	}
	return e, nil
}

func setElements(s Set) []nftables.SetElement {
	var out []nftables.SetElement
	for _, r := range s.Ranges {
		out = append(out, nftables.SetElement{Key: r.From().AsSlice()})
		if next := r.To().Next(); next.IsValid() {
			out = append(out, nftables.SetElement{Key: next.AsSlice(), IntervalEnd: true})
		}
	}
	return out
}

func exists(conn *nftables.Conn) (bool, error) {
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(tables, func(t *nftables.Table) bool { return t.Name == Table }), nil
}

// Apply replaces the table with plan in one netlink batch: the kernel
// applies the whole batch or nothing, so a failed update leaves the
// previous rules in force and there is no moment without them.
func Apply(plan Plan) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	have, err := exists(conn)
	if err != nil {
		return err
	}
	t := table()
	if have {
		conn.DelTable(t)
	}
	conn.AddTable(t)
	sets := map[string]*nftables.Set{}
	for i, s := range plan.Sets {
		key := nftables.TypeIPAddr
		if s.V6 {
			key = nftables.TypeIP6Addr
		}
		set := &nftables.Set{Table: t, Name: s.Name, ID: uint32(i + 1), KeyType: key, Interval: true, Constant: true}
		if err := conn.AddSet(set, setElements(s)); err != nil {
			return fmt.Errorf("set %s: %w", s.Name, err)
		}
		sets[s.Name] = set
	}
	accept := nftables.ChainPolicyAccept
	chain := conn.AddChain(&nftables.Chain{Name: Chain, Table: t, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter, Policy: &accept})
	for _, r := range plan.Rules {
		e, err := ruleExprs(r, sets)
		if err != nil {
			return err
		}
		conn.AddRule(&nftables.Rule{Table: t, Chain: chain, Exprs: e, UserData: userdata.AppendString(nil, userdata.TypeComment, r.Label)})
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("load the protection table: %w", err)
	}
	return nil
}

// Remove deletes the table. Other tables are never touched.
func Remove() error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	have, err := exists(conn)
	if err != nil || !have {
		return err
	}
	conn.DelTable(table())
	return conn.Flush()
}

// RuleState is a loaded rule with its counters.
type RuleState struct {
	Label          string
	Packets, Bytes uint64
}

// State is what the kernel holds.
type State struct {
	Known  bool
	Exists bool
	Rules  []RuleState
	Sets   map[string][]string
	Err    error
}

// Inspect reads the table.
func Inspect() State {
	conn, err := nftables.New()
	if err != nil {
		return State{Err: err}
	}
	have, err := exists(conn)
	if err != nil {
		return State{Err: err}
	}
	st := State{Known: true, Exists: have, Sets: map[string][]string{}}
	if !have {
		return st
	}
	t := table()
	rules, err := conn.GetRules(t, &nftables.Chain{Name: Chain, Table: t})
	if err != nil {
		st.Err = err
		return st
	}
	for _, r := range rules {
		rs := RuleState{}
		rs.Label, _ = userdata.GetString(r.UserData, userdata.TypeComment)
		for _, e := range r.Exprs {
			if c, ok := e.(*expr.Counter); ok {
				rs.Packets, rs.Bytes = c.Packets, c.Bytes
			}
		}
		st.Rules = append(st.Rules, rs)
	}
	if sets, err := conn.GetSets(t); err == nil {
		for _, s := range sets {
			elems, err := conn.GetSetElements(s)
			if err != nil {
				continue
			}
			st.Sets[s.Name] = elementStrings(elems)
		}
	}
	return st
}

// elementStrings renders interval set elements as ranges or prefixes.
func elementStrings(elems []nftables.SetElement) []string {
	type point struct {
		addr []byte
		end  bool
	}
	pts := make([]point, 0, len(elems))
	for _, e := range elems {
		pts = append(pts, point{e.Key, e.IntervalEnd})
	}
	slices.SortFunc(pts, func(a, b point) int { return slices.Compare(a.addr, b.addr) })
	var out []string
	for i := 0; i < len(pts); i++ {
		if pts[i].end {
			continue
		}
		from := net.IP(pts[i].addr)
		if i+1 < len(pts) && pts[i+1].end {
			out = append(out, rangeString(from, pts[i+1].addr))
			i++
		} else {
			out = append(out, from.String()+"-")
		}
	}
	return out
}

// Chain is a base chain of any table, for the system view.
type ChainInfo struct {
	Family, Table, Name string
	Hook                string
	Priority            int32
	Policy              string
	Yuhaiin             bool
}

// Chains lists every base chain of the system, as nft evaluates them per
// hook in priority order.
func Chains() ([]ChainInfo, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}
	chains, err := conn.ListChains()
	if err != nil {
		return nil, err
	}
	var out []ChainInfo
	for _, c := range chains {
		if c.Hooknum == nil || c.Table == nil {
			continue
		}
		ci := ChainInfo{Family: familyName(c.Table.Family), Table: c.Table.Name, Name: c.Name, Hook: hookName(*c.Hooknum), Yuhaiin: c.Table.Name == Table}
		if c.Priority != nil {
			ci.Priority = int32(*c.Priority)
		}
		if c.Policy != nil {
			ci.Policy = map[nftables.ChainPolicy]string{nftables.ChainPolicyAccept: "accept", nftables.ChainPolicyDrop: "drop"}[*c.Policy]
		}
		out = append(out, ci)
	}
	slices.SortStableFunc(out, func(a, b ChainInfo) int {
		if a.Hook != b.Hook {
			return strings.Compare(hookOrder(a.Hook), hookOrder(b.Hook))
		}
		return int(a.Priority) - int(b.Priority)
	})
	return out, nil
}

func familyName(f nftables.TableFamily) string {
	return map[nftables.TableFamily]string{nftables.TableFamilyINet: "inet", nftables.TableFamilyIPv4: "ip", nftables.TableFamilyIPv6: "ip6",
		nftables.TableFamilyARP: "arp", nftables.TableFamilyBridge: "bridge", nftables.TableFamilyNetdev: "netdev"}[f]
}

func hookName(h nftables.ChainHook) string {
	switch h {
	case *nftables.ChainHookPrerouting:
		return "prerouting"
	case *nftables.ChainHookInput:
		return "input"
	case *nftables.ChainHookForward:
		return "forward"
	case *nftables.ChainHookOutput:
		return "output"
	case *nftables.ChainHookPostrouting:
		return "postrouting"
	}
	return fmt.Sprint(uint32(h))
}

func hookOrder(h string) string {
	return map[string]string{"output": "0", "postrouting": "1", "prerouting": "2", "input": "3", "forward": "4"}[h] + h
}
