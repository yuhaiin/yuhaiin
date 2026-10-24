package auth

import (
	"net/http"
	"strconv"
)

func (s *Server) registerRoles(register func(string, Permission, http.HandlerFunc)) {
	register("GET /api/v2/auth/roles", RolesRead, func(w http.ResponseWriter, r *http.Request) {
		roles, err := s.Store.Roles(r.Context())
		respond(w, roles, err)
	})
	register("POST /api/v2/auth/roles", RolesWrite, func(w http.ResponseWriter, r *http.Request) {
		var role Role
		if !decode(r, w, &role) {
			return
		}
		if role.ID != "" {
			respond(w, nil, ErrInvalid)
			return
		}
		actor, _ := FromContext(r.Context())
		out, err := s.Store.SaveRole(r.Context(), actor, role)
		respond(w, out, err)
	})
	register("PUT /api/v2/auth/roles/{id}", RolesWrite, func(w http.ResponseWriter, r *http.Request) {
		var role Role
		if !decode(r, w, &role) {
			return
		}
		if role.ID != "" && role.ID != r.PathValue("id") {
			respond(w, nil, ErrInvalid)
			return
		}
		role.ID = r.PathValue("id")
		actor, _ := FromContext(r.Context())
		out, err := s.Store.SaveRole(r.Context(), actor, role)
		respond(w, out, err)
	})
	register("DELETE /api/v2/auth/roles/{id}", RolesWrite, func(w http.ResponseWriter, r *http.Request) {
		revision, err := strconv.ParseUint(r.URL.Query().Get("revision"), 10, 64)
		if err != nil {
			respond(w, nil, ErrInvalid)
			return
		}
		actor, _ := FromContext(r.Context())
		respond(w, struct{}{}, s.Store.DeleteRole(r.Context(), actor, r.PathValue("id"), revision))
	})
	register("GET /api/v2/auth/users/{id}/roles", RolesRead, func(w http.ResponseWriter, r *http.Request) {
		actor, _ := FromContext(r.Context())
		out, err := s.Store.RoleAssignment(r.Context(), actor, r.PathValue("id"))
		respond(w, out, err)
	})
	register("PUT /api/v2/auth/users/{id}/roles", RolesWrite, func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			RoleIDs  []string `json:"roleIds"`
			Revision uint64   `json:"revision"`
		}
		if !decode(r, w, &request) {
			return
		}
		actor, _ := FromContext(r.Context())
		out, err := s.Store.AssignRoles(r.Context(), actor, r.PathValue("id"), request.Revision, request.RoleIDs)
		respond(w, out, err)
	})
}
