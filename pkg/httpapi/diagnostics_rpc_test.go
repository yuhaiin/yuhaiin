package httpapi

import (
	"context"
	"errors"
	"testing"

	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
	managementpermission "github.com/Asutorufa/yuhaiin/pkg/management/permission"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
)

type recentLogTools struct{ ToolsController }

func (recentLogTools) RecentLogs(context.Context, contracttools.LogQuery) (contracttools.RecentLogs, error) {
	return contracttools.RecentLogs{Lines: []string{"line"}}, nil
}

func TestRecentLogsEnforcesSecretRetrieval(t *testing.T) {
	ops := NewOperations(V2Services{Tools: recentLogTools{}})
	diagnostics := managementpermission.WithGranted(t.Context(), []managementpermission.Permission{managementpermission.Diagnostics})
	if permission, ok := ops.Permission("logs.recent"); !ok || permission != managementpermission.Diagnostics {
		t.Fatal(permission, ok)
	}
	// Without the identity module there is no secret capability to check.
	if _, err := ops.Invoke(diagnostics, "logs.recent", nil); err != nil {
		t.Fatal(err)
	}
	managed := secret.WithCapabilities(diagnostics, secret.Capabilities{})
	if _, err := ops.Invoke(managed, "logs.recent", nil); !errors.Is(err, secret.ErrRetrieval) {
		t.Fatalf("managed request without the retrieval capability: %v", err)
	}
	if status, code, _ := ErrorStatus(secret.ErrRetrieval); status != 403 || code != "permission_denied" {
		t.Fatal(status, code)
	}
	authorized := []string{}
	allowed := secret.WithCapabilities(diagnostics, secret.Capabilities{AuthorizeRetrieval: func(_ context.Context, resource string) error {
		authorized = append(authorized, resource)
		return nil
	}})
	if _, err := ops.Invoke(allowed, "logs.recent", []byte(`{"limit":5,"level":"warn"}`)); err != nil || len(authorized) != 1 || authorized[0] != "logs.recent" {
		t.Fatal(err, authorized)
	}
	for _, body := range []string{`{"limit":5000}`, `{"level":"loud"}`} {
		if _, err := ops.Invoke(allowed, "logs.recent", []byte(body)); err == nil {
			t.Errorf("%s accepted", body)
		}
	}
	if _, err := ops.Invoke(diagnostics, "runtime.stats", nil); err == nil {
		t.Fatal("runtime.stats ran without metrics:read")
	}
	metrics := managementpermission.WithGranted(t.Context(), []managementpermission.Permission{managementpermission.MetricsRead})
	if _, err := ops.Invoke(metrics, "runtime.stats", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.Invoke(diagnostics, "profiler.sessions", nil); err == nil {
		t.Fatal("missing profiler reported success")
	}
}
