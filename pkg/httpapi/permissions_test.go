package httpapi

import (
	"testing"
)

func TestEveryRegisteredActionHasReviewedPermission(t *testing.T) {
	permissions := ManagementPermissions()
	for _, route := range v2Routes {
		pattern := v2RoutePattern(route)
		permission := permissions[pattern]
		if permission == "" {
			t.Errorf("unclassified actual registration: %s (%s)", pattern, route.endpoint)
		}
	}
	if len(permissions) != len(v2Routes) {
		t.Fatal("route registry contains duplicate actual patterns")
	}
}
