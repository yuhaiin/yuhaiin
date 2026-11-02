//go:build linux && !android

package sshserver

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSSHStartupErrorReasonDoesNotExposeErrorText(t *testing.T) {
	for _, tc := range []struct {
		err error
		want string
	}{
		{fmt.Errorf("credential leakage risk: %w", unix.EPERM), "permission_denied"},
		{fmt.Errorf("password=secret: %w", unix.EINVAL), "invalid_argument"},
		{fmt.Errorf("authKey=secret: %w", unix.ENOENT), "not_found"},
		{context.Canceled, "canceled"},
		{errors.New("password=secret"), "unknown"},
	} {
		if got := sshStartupErrorReason(tc.err); got != tc.want {
			t.Fatalf("unexpected classification %q: wanted %q", got, tc.want)
		}
	}
}
