package inbound

import (
	"context"
	"net"

	connection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
)

func WithUserUsage(recorder *statistics.UserUsage) Option {
	return func(l *Inbound) { l.usage = recorder }
}

func stringerAddress(address net.Addr) string {
	if address == nil {
		return ""
	}
	return address.String()
}

func (l *Inbound) localDNSUsage(identity *proxyauth.Identity, source string, target netapi.Address, inboundID, inboundName, protocol string) *statistics.LocalUsage {
	if l.usage == nil {
		return nil
	}
	info := connection.Connection{Source: source, Addr: target.String(), InboundID: inboundID, InboundName: inboundName, NodeID: "@local-dns", NodeName: "Local DNS", Mode: "dns", Network: connection.NetworkType{ConnType: protocol}}
	var lifetime context.Context
	if identity != nil {
		info.UserID, info.CredentialID = identity.UserID, identity.CredentialID
		info.GroupIDs = identity.GroupIDs
		lifetime = identity.Context
	}
	return l.usage.Local(info, lifetime)
}
