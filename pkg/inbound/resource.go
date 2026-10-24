package inbound

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

func (s *handler) admitStream(ctx *netapi.Context, inboundID string) (*trafficcontrol.StreamLease, bool) {
	if identity := netapi.TrafficIdentity(ctx); identity != nil {
		return s.control.AdmitIdentityStream(inboundID, identity.UserID, identity.CredentialID)
	}
	return s.control.AdmitStream(inboundID)
}

func (s *handler) resolvePolicy(ctx *netapi.Context, inboundID, routeID string) trafficcontrol.Policy {
	if identity := netapi.TrafficIdentity(ctx); identity != nil {
		return s.control.ResolveAuthenticated(inboundID, routeID, identity)
	}
	return s.control.Resolve(inboundID, routeID)
}
