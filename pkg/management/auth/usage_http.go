package auth

import (
	"errors"
	"net/http"
	"strconv"

	usage "github.com/Asutorufa/yuhaiin/pkg/contract/usage"
)

func usageRequest(r *http.Request, p Principal) (usage.Query, error) {
	values := r.URL.Query()
	owner := values.Get("owner")
	if owner == "" {
		owner = p.UserID
	}
	if owner != p.UserID && !p.Allows(UsageRead) {
		return usage.Query{}, ErrForbidden
	}
	if owner == "unattributed" {
		owner = ""
	}
	q := usage.Query{UserID: owner, Interval: values.Get("interval"), CredentialID: values.Get("credentialId"), InboundID: values.Get("inboundId"), NodeID: values.Get("nodeId"), Protocol: values.Get("protocol"), Result: values.Get("result"), Source: values.Get("source"), Target: values.Get("target"), Before: values.Get("before")}
	for _, field := range []struct {
		name string
		out  *int64
	}{{"from", &q.From}, {"to", &q.To}} {
		if raw := values.Get(field.name); raw != "" {
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || n < 0 || n > 1<<40 {
				return q, ErrInvalid
			}
			*field.out = n
		}
	}
	if raw := values.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return q, ErrInvalid
		}
		q.Limit = n
	}
	for _, value := range []string{q.UserID, q.CredentialID, q.InboundID, q.NodeID, q.Protocol, q.Result} {
		if len(value) > 128 {
			return q, ErrInvalid
		}
	}
	return q, nil
}

func usageError(err error) error {
	if errors.Is(err, usage.ErrQuery) {
		return ErrInvalid
	}
	return err
}

func (s *Server) registerUsage(register func(string, Permission, http.HandlerFunc)) {
	if s.Usage == nil {
		return
	}
	register("GET /api/v2/auth/usage", UsageOwn, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		q, err := usageRequest(r, p)
		if err != nil {
			respond(w, nil, err)
			return
		}
		out, err := s.Usage.Report(r.Context(), q)
		if err == nil && s.Proxy != nil && q.UserID != "" {
			credentials, listErr := s.Proxy.List(r.Context(), q.UserID)
			if listErr != nil {
				respond(w, nil, listErr)
				return
			}
			names := make(map[string]string, len(credentials))
			for _, c := range credentials {
				names[c.ID] = c.Name
			}
			for i := range out.Credentials {
				if name := names[out.Credentials[i].ID]; name != "" {
					out.Credentials[i].Name = name
				}
			}
		}
		respond(w, out, usageError(err))
	})
	register("GET /api/v2/auth/usage/audit", UsageOwn, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		q, err := usageRequest(r, p)
		if err != nil {
			respond(w, nil, err)
			return
		}
		out, err := s.Usage.Audit(r.Context(), q)
		respond(w, out, usageError(err))
	})
	register("GET /api/v2/auth/usage/owners", UsageRead, func(w http.ResponseWriter, r *http.Request) {
		out, err := s.Usage.UsageUsers(r.Context(), r.URL.Query().Get("after"), 200)
		respond(w, out, usageError(err))
	})
	register("GET /api/v2/auth/usage/settings", UsageOwn, func(w http.ResponseWriter, _ *http.Request) { respond(w, s.Usage.Options(), nil) })
	register("PUT /api/v2/auth/usage/settings", UsersManage, func(w http.ResponseWriter, r *http.Request) {
		var options usage.Options
		if !decode(r, w, &options) {
			return
		}
		err := s.Usage.SetOptions(r.Context(), options)
		if err == nil {
			p, _ := FromContext(r.Context())
			s.Store.audit(r.Context(), "usage.retention_updated", p.UserID, "")
		}
		respond(w, options, usageError(err))
	})
}
