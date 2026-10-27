//go:build linux || darwin || windows

package main

import (
	"context"
	"errors"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	"path/filepath"
	"strings"
)

func validateUpdateStaging(target, staged string) error {
	name := filepath.Base(staged)
	if !filepath.IsAbs(target) || !filepath.IsAbs(staged) || filepath.Dir(target) != filepath.Dir(staged) ||
		(!strings.HasPrefix(name, "yuhaiin-update-") && !strings.HasPrefix(name, ".yuhaiin-rollback-")) {
		return errors.New("update helper requires its private managed staging beside the installed executable")
	}
	return nil
}

func (u *serviceUpdateInstaller) InspectCompatibility(ctx context.Context, m compatibility.Manifest) (contract.CompatibilityStatus, error) {
	return m.Check(ctx, u.dataDir)
}
