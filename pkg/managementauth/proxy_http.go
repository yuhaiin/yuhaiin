package managementauth

import "net/http"

func (s *Server) registerProxyCredentials(register func(string, Permission, http.HandlerFunc)) {
	if s.Proxy != nil {
		register("GET /api/v2/auth/proxy-credentials", ProxyCredentialsOwn, func(w http.ResponseWriter, r *http.Request) {
			p, _ := FromContext(r.Context())
			owner := r.URL.Query().Get("owner")
			if owner == "" {
				owner = p.UserID
			}
			if owner != p.UserID && !p.Allows(ProxyCredentialsManage) {
				authError(w, http.StatusForbidden)
				return
			}
			out, err := s.Proxy.List(r.Context(), owner)
			respond(w, out, err)
		})
		register("POST /api/v2/auth/proxy-credentials", ProxyCredentialsOwn, func(w http.ResponseWriter, r *http.Request) {
			var request ProxyCredentialRequest
			if !decode(r, w, &request) {
				return
			}
			p, _ := FromContext(r.Context())
			out, err := s.Proxy.Issue(r.Context(), p, request)
			respond(w, out, err)
		})
		register("DELETE /api/v2/auth/proxy-credentials/{id}", ProxyCredentialsOwn, func(w http.ResponseWriter, r *http.Request) {
			p, _ := FromContext(r.Context())
			respond(w, struct{}{}, s.Proxy.Revoke(r.Context(), p, r.PathValue("id")))
		})
		register("POST /api/v2/auth/proxy-credentials/{id}/rotate", ProxyCredentialsOwn, func(w http.ResponseWriter, r *http.Request) {
			p, _ := FromContext(r.Context())
			out, err := s.Proxy.Rotate(r.Context(), p, r.PathValue("id"))
			respond(w, out, err)
		})
	}
	if s.Upstream != nil {
		register("GET /api/v2/auth/upstream-credentials", UpstreamCredentialsManage, func(w http.ResponseWriter, r *http.Request) {
			out, err := s.Upstream.List(r.Context())
			respond(w, out, err)
		})
		register("POST /api/v2/auth/upstream-credentials", UpstreamCredentialsManage, func(w http.ResponseWriter, r *http.Request) {
			var request UpstreamCredentialRequest
			if !decode(r, w, &request) {
				return
			}
			p, _ := FromContext(r.Context())
			out, err := s.Upstream.Save(r.Context(), p, "", request)
			respond(w, out, err)
		})
		register("PUT /api/v2/auth/upstream-credentials/{id}", UpstreamCredentialsManage, func(w http.ResponseWriter, r *http.Request) {
			var request UpstreamCredentialRequest
			if !decode(r, w, &request) {
				return
			}
			p, _ := FromContext(r.Context())
			out, err := s.Upstream.Save(r.Context(), p, r.PathValue("id"), request)
			respond(w, out, err)
		})
		register("DELETE /api/v2/auth/upstream-credentials/{id}", UpstreamCredentialsManage, func(w http.ResponseWriter, r *http.Request) {
			p, _ := FromContext(r.Context())
			respond(w, struct{}{}, s.Upstream.Delete(r.Context(), p, r.PathValue("id")))
		})
	}
}
