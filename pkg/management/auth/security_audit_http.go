package auth

import (
	"context"
	"net/http"
	"strconv"
)

func auditHTTPQuery(r *http.Request) (AuditQuery, error) {
	v := r.URL.Query()
	q := AuditQuery{Cursor: v.Get("cursor"), Event: v.Get("event"), ActorID: v.Get("actorId"), SubjectID: v.Get("subjectId"), Result: v.Get("result"), AuthMethod: v.Get("authMethod"), Reason: v.Get("reason"), Search: v.Get("search")}
	var err error
	if value := v.Get("limit"); value != "" {
		q.Limit, err = strconv.Atoi(value)
		if err != nil {
			return q, ErrInvalid
		}
	}
	if value := v.Get("from"); value != "" {
		q.From, err = strconv.ParseInt(value, 10, 64)
		if err != nil {
			return q, ErrInvalid
		}
	}
	if value := v.Get("to"); value != "" {
		q.To, err = strconv.ParseInt(value, 10, 64)
		if err != nil {
			return q, ErrInvalid
		}
	}
	return q, nil
}
func (s *Store) auditExport(ctx context.Context, actor Principal, q AuditQuery) (AuditPage, error) {
	// Capture the bounded page before adding the authorization event, and release
	// its DB connection before writing the durable intent or the HTTP response.
	page, err := s.AuditPage(ctx, q)
	if err != nil {
		return AuditPage{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuditPage{}, err
	}
	defer func() { _ = tx.Rollback() }()
	actor, err = freshRoleActor(ctx, tx, actor)
	if err != nil || !actor.Allows(SecurityExport) {
		return AuditPage{}, ErrForbidden
	}
	if err = recordEvent(ctx, tx, "security.audit_export_authorized", actor.UserID, "management-audit"); err != nil {
		return AuditPage{}, err
	}
	if err = tx.Commit(); err != nil {
		return AuditPage{}, err
	}
	return page, nil
}
func (s *Server) registerSecurityAudit(register func(string, Permission, http.HandlerFunc)) {
	register("GET /api/v2/auth/events/page", SecurityRead, func(w http.ResponseWriter, r *http.Request) {
		q, err := auditHTTPQuery(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		out, err := s.Store.AuditPage(r.Context(), q)
		respond(w, out, err)
	})
	register("GET /api/v2/auth/events/export", SecurityExport, func(w http.ResponseWriter, r *http.Request) {
		q, err := auditHTTPQuery(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		p, _ := FromContext(r.Context())
		out, err := s.Store.auditExport(r.Context(), p, q)
		if err == nil {
			w.Header().Set("Content-Disposition", `attachment; filename="management-security-audit.json"`)
		}
		respond(w, out, err)
	})
	register("GET /api/v2/auth/events/settings", SecurityRead, func(w http.ResponseWriter, r *http.Request) {
		out, err := s.Store.AuditSettings(r.Context())
		respond(w, out, err)
	})
	register("PUT /api/v2/auth/events/settings", SecurityWrite, func(w http.ResponseWriter, r *http.Request) {
		var in AuditSettingsRequest
		if !decode(r, w, &in) {
			return
		}
		p, _ := FromContext(r.Context())
		out, err := s.Store.SaveAuditSettings(r.Context(), p, in)
		respond(w, out, err)
	})
	register("GET /api/v2/auth/events/status", SecurityRead, func(w http.ResponseWriter, r *http.Request) {
		out, err := s.Store.AuditStatus(r.Context())
		respond(w, out, err)
	})
}
