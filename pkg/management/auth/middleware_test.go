package auth

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
)

func TestInitializationNoticeHidesConfiguredSecret(t *testing.T) {
	code := InitializationCode{Secret: "ys_test_secret", ExpiresAt: time.Now().Add(15 * time.Minute).Unix()}
	for _, configured := range []bool{false, true} {
		var output bytes.Buffer
		if err := writeInitializationNotice(&output, code, configured); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), code.Secret) == configured {
			t.Fatalf("unexpected secret visibility for configured=%t", configured)
		}
		if !strings.Contains(output.String(), time.Unix(code.ExpiresAt, 0).Format(time.RFC3339)) {
			t.Fatal("initialization notice omitted expiry")
		}
		restart := "replaces this code"
		if configured {
			restart = "renews the configured code"
		}
		if !strings.Contains(output.String(), restart) {
			t.Fatal("initialization notice described the wrong restart behavior")
		}
	}
	if err := writeInitializationNotice(io.Discard, code, true); err != nil {
		t.Fatal(err)
	}
	if err := writeInitializationNotice(failedInitializationOutput{}, code, true); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("output failure was not propagated: %v", err)
	}
}

type failedInitializationOutput struct{}

func (failedInitializationOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestRPCPermissionAnnotationsBelongToKnownScopes(t *testing.T) {
	known := RolePermissions(Admin)
	for pattern, scope := range httpapi.ManagementPermissions() {
		if !slices.Contains(known, Permission(scope)) {
			t.Errorf("unknown permission %q on %s", scope, pattern)
		}
	}
}
