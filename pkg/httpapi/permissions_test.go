package httpapi

import (
	"slices"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/managementauth"
)

func TestEveryRegisteredActionHasReviewedPermission(t *testing.T) {
	permissions := ManagementPermissions()
	known := managementauth.RolePermissions(managementauth.Admin)
	for _, route := range v2Routes {
		pattern := v2RoutePattern(route)
		permission := permissions[pattern]
		if permission == "" || !slices.Contains(known, permission) {
			t.Errorf("unclassified actual registration: %s (%s)", pattern, route.endpoint)
		}
	}
	if len(permissions) != len(v2Routes) {
		t.Fatal("route registry contains duplicate actual patterns")
	}
}
