package auth

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/management/permission"
)

func TestManagementActorContextPreservesPrincipalBoundary(t *testing.T) {
	actorOnly := permission.WithActorID(t.Context(), "actor-only")
	if _, ok := FromContext(actorOnly); ok {
		t.Fatal("actor metadata granted an authentication principal")
	}
	principal := Principal{UserID: "authenticated", CredentialID: "fixture", Permissions: []Permission{BackupManage}}
	ctx := WithPrincipal(actorOnly, principal)
	got, ok := FromContext(ctx)
	if !ok || got.UserID != principal.UserID || !got.Allows(BackupManage) || got.Allows(UsersManage) || permission.ActorID(ctx) != principal.UserID {
		t.Fatal("host principal identity or permissions changed at the lightweight boundary")
	}
	if id := permission.ActorID(WithPrincipal(ctx, Principal{})); id != "" {
		t.Fatal("replacing a principal retained the previous actor identifier")
	}
}
