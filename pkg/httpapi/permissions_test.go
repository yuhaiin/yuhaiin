package httpapi

import (
	"testing"

	managementpermission "github.com/Asutorufa/yuhaiin/pkg/managementauth/permission"
)

func TestEveryRegisteredActionHasReviewedPermission(t *testing.T) {
	permissions := ManagementPermissions()
	known := make(map[managementpermission.Permission]bool)
	for _, definition := range managementpermission.Catalog() {
		known[definition.ID] = true
	}
	for _, route := range v2Routes {
		pattern := v2RoutePattern(route)
		permission := permissions[pattern]
		if permission == "" {
			t.Errorf("unclassified actual registration: %s (%s)", pattern, route.endpoint)
			continue
		}
		if !known[permission] {
			t.Errorf("route %s uses permission %q missing from catalog", pattern, permission)
		}
	}
	if len(permissions) != len(v2Routes) {
		t.Fatal("route registry contains duplicate actual patterns")
	}
}
