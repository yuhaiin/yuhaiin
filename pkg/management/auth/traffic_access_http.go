package auth

import (
	"net"
	"net/http"
	"net/netip"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type AccessPreviewRequest struct {
	CredentialID string `json:"credentialId"`
	InboundID    string `json:"inboundId"`
	Protocol     string `json:"protocol"`
	Destination  string `json:"destination"`
	ResolvedIP   string `json:"resolvedIp"`
}

func (s *Server) registerTrafficAccess(register func(string, Permission, http.HandlerFunc)) {
	if s.Access == nil {
		return
	}
	register("GET /api/v2/auth/traffic-access", TrafficAccessRead, func(w http.ResponseWriter, r *http.Request) { respond(w, s.Access.Controller.Config(), nil) })
	register("GET /api/v2/auth/traffic-access/status", TrafficAccessRead, func(w http.ResponseWriter, r *http.Request) { respond(w, s.Access.Controller.Status(), nil) })
	register("POST /api/v2/auth/traffic-access/validate", TrafficAccessWrite, func(w http.ResponseWriter, r *http.Request) {
		var config contract.Config
		if !decode(r, w, &config) {
			return
		}
		respond(w, s.Access.Validate(r.Context(), config), nil)
	})
	register("PUT /api/v2/auth/traffic-access", TrafficAccessWrite, func(w http.ResponseWriter, r *http.Request) {
		var config contract.Config
		if !decode(r, w, &config) {
			return
		}
		actor, _ := FromContext(r.Context())
		out, err := s.Access.Save(r.Context(), actor, config)
		respond(w, out, err)
	})
	register("POST /api/v2/auth/traffic-access/preview", TrafficAccessRead, func(w http.ResponseWriter, r *http.Request) {
		var request AccessPreviewRequest
		if !decode(r, w, &request) {
			return
		}
		if s.Proxy == nil || (request.Protocol != "tcp" && request.Protocol != "udp") || request.InboundID == "" {
			respond(w, nil, ErrInvalid)
			return
		}
		original, err := netapi.ParseAddress(request.Protocol, request.Destination)
		if err != nil {
			respond(w, nil, ErrInvalid)
			return
		}
		ip, err := netip.ParseAddr(request.ResolvedIP)
		if err != nil || ip.Zone() != "" {
			respond(w, nil, ErrInvalid)
			return
		}
		actor, _ := FromContext(r.Context())
		s.Proxy.mu.RLock()
		record := s.Proxy.records[request.CredentialID]
		if record == nil || !record.identity.Valid() {
			s.Proxy.mu.RUnlock()
			respond(w, nil, ErrInvalid)
			return
		}
		if actor.UserID != record.UserID && !actor.Allows(UsersManage) {
			s.Proxy.mu.RUnlock()
			respond(w, nil, ErrForbidden)
			return
		}
		identity := record.identity
		s.Proxy.mu.RUnlock()
		actual := netapi.ParseIPAddr(request.Protocol, net.IP(ip.Unmap().AsSlice()), original.Port())
		respond(w, s.Access.Controller.Preview(netapi.TrafficSubject{Identity: identity, InboundID: request.InboundID, External: true}, original, actual), nil)
	})
}
