package auth

import (
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
)

func (s *Server) registerResources(register func(string, Permission, http.HandlerFunc)) {
	if s.Resources == nil {
		return
	}
	register("GET /api/v2/auth/usage/resources", UsageOwn, func(w http.ResponseWriter, r *http.Request) {
		actor, _ := FromContext(r.Context())
		q, err := usageRequest(r, actor)
		if err != nil {
			respond(w, nil, err)
			return
		}
		out, err := s.Resources.Report(r.Context(), q.UserID, q.CredentialID)
		respond(w, out, err)
	})
	register("GET /api/v2/auth/usage/resource-alerts", UsageOwn, func(w http.ResponseWriter, r *http.Request) {
		actor, _ := FromContext(r.Context())
		q, err := usageRequest(r, actor)
		if err != nil {
			respond(w, nil, err)
			return
		}
		out, err := s.Resources.Alerts(r.Context(), q.UserID, q.Before, q.Limit)
		respond(w, out, err)
	})
	register("GET /api/v2/auth/resources", ResourceRead, func(w http.ResponseWriter, r *http.Request) { respond(w, s.Resources.Control.ResourceConfig(), nil) })
	register("GET /api/v2/auth/resources/status", ResourceRead, func(w http.ResponseWriter, r *http.Request) { respond(w, s.Resources.Status(), nil) })
	register("POST /api/v2/auth/resources/validate", ResourceWrite, func(w http.ResponseWriter, r *http.Request) {
		var config resource.Config
		if !decode(r, w, &config) {
			return
		}
		respond(w, s.Resources.Validate(r.Context(), config), nil)
	})
	register("PUT /api/v2/auth/resources", ResourceWrite, func(w http.ResponseWriter, r *http.Request) {
		var config resource.Config
		if !decode(r, w, &config) {
			return
		}
		actor, _ := FromContext(r.Context())
		out, err := s.Resources.Save(r.Context(), actor, config)
		respond(w, out, err)
	})
}
