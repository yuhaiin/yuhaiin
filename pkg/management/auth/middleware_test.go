package auth

import (
	"slices"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
)

func TestRPCPermissionAnnotationsBelongToKnownScopes(t *testing.T) {
	known := RolePermissions(Admin)
	for pattern, scope := range httpapi.ManagementPermissions() {
		if !slices.Contains(known, Permission(scope)) {
			t.Errorf("unknown permission %q on %s", scope, pattern)
		}
	}
}
