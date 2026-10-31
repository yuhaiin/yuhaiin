package auth

import (
	"context"
	"encoding/json/v2"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
)

// This compares the existing owner mutator against optional journal/authority
// work on the same schema and FULL synchronous mode. It excludes proxy reload.
func BenchmarkConfigurationGroupChange(b *testing.B) {
	for _, mode := range []string{"owner-only", "managed-history", "stage-validate-commit"} {
		b.Run(mode, func(b *testing.B) {
			s := benchmarkAuditStore(b)
			seedAuditHistory(b, s)
			user, _, err := s.CreateUser(b.Context(), "local", "benchmark", Admin, false)
			if err != nil {
				b.Fatal(err)
			}
			if _, err = s.db.ExecContext(b.Context(), `UPDATE management_users SET credential='benchmark-only' WHERE id=?`, user.ID); err != nil {
				b.Fatal(err)
			}
			p := principal(user)
			c := &ConfigurationChanges{server: &Server{Store: s}, identity: configchange.New(s.db)}
			group, err := s.SaveGroup(b.Context(), p, "", GroupRequest{Name: "Benchmark"})
			if err != nil {
				b.Fatal(err)
			}
			ctx := b.Context()
			if mode != "owner-only" {
				ctx = c.actorContext(ctx, p)
			}
			b.ReportAllocs()
			for b.Loop() {
				request := GroupRequest{Name: "Benchmark", Description: "updated", Revision: group.Revision}
				if mode == "stage-validate-commit" {
					raw, err := json.Marshal(request)
					if err != nil {
						b.Fatal(err)
					}
					stage, err := c.stageIdentity(ctx, p, "group", group.ID, "save", raw)
					if err != nil {
						b.Fatal(err)
					}
					d, err := c.identity.Payload(ctx, stage.ID)
					if err != nil {
						b.Fatal(err)
					}
					apply := func(ctx context.Context) error { return c.applyIdentityDocument(ctx, p, d, false) }
					if err = c.identity.Validate(ctx, stage.ID, apply); err != nil {
						b.Fatal(err)
					}
					if _, err = c.identity.Commit(ctx, stage.ID, apply); err != nil {
						b.Fatal(err)
					}
					group.Revision++
				} else {
					group, err = s.SaveGroup(ctx, p, group.ID, request)
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
