//go:build darwin

package updatecmd

import (
	"context"
	"github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/servicehost"
	"time"
)

func (u *serviceUpdateInstaller) StartProtected(ctx context.Context, id string) error {
	return servicehost.StartDarwinMaintenance(ctx, u.dataDir, id, 24*time.Hour+5*time.Minute, "update-protected-helper")
}

type protectedUpdateService struct{ directory string }

func (s protectedUpdateService) Stop(ctx context.Context) error {
	return (servicehost.DarwinService{Directory: s.directory}).Stop(ctx)
}
func (s protectedUpdateService) Start(ctx context.Context) error {
	return (servicehost.DarwinService{Directory: s.directory}).Start(ctx)
}
func (s protectedUpdateService) MainPID(ctx context.Context) (int, error) {
	return (servicehost.DarwinService{Directory: s.directory}).MainPID(ctx)
}
