package auth

import (
	"net/http"
	"strconv"
)

func (s *Server) registerGroups(register func(string, Permission, http.HandlerFunc)) {
	register("GET /api/v2/auth/groups", UsersManage, func(w http.ResponseWriter, r *http.Request) {
		out, err := s.Store.Groups(r.Context())
		respond(w, out, err)
	})
	register("GET /api/v2/auth/groups/{id}", UsersManage, func(w http.ResponseWriter, r *http.Request) {
		out, err := s.Store.Group(r.Context(), r.PathValue("id"))
		respond(w, out, err)
	})
	save := func(w http.ResponseWriter, r *http.Request) {
		var request GroupRequest
		if !decode(r, w, &request) {
			return
		}
		p, _ := FromContext(r.Context())
		out, err := s.Store.SaveGroup(r.Context(), p, r.PathValue("id"), request)
		if err == nil && s.Proxy != nil {
			err = s.Proxy.Reload()
		}
		respond(w, out, err)
	}
	register("POST /api/v2/auth/groups", UsersManage, save)
	register("PUT /api/v2/auth/groups/{id}", UsersManage, save)
	register("DELETE /api/v2/auth/groups/{id}", UsersManage, func(w http.ResponseWriter, r *http.Request) {
		revision, err := strconv.ParseUint(r.URL.Query().Get("revision"), 10, 64)
		if err != nil {
			respond(w, nil, ErrInvalid)
			return
		}
		p, _ := FromContext(r.Context())
		err = s.Store.DeleteGroup(r.Context(), p, r.PathValue("id"), revision)
		if err == nil && s.Proxy != nil {
			err = s.Proxy.Reload()
		}
		respond(w, struct{}{}, err)
	})
}
