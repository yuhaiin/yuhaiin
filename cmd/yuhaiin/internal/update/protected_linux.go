//go:build linux

package updatecmd

import (
	"context"
	"errors"
	"github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/servicehost"
	"os"
	"strconv"
	"strings"
	"uuid"
)

func (u *serviceUpdateInstaller) StartProtected(ctx context.Context, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != id || parsed == (uuid.UUID{}) {
		return errors.New("invalid update operation")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// RuntimeMax and independent ExecStopPost also handle SIGKILL and host restart.
	restart := strconv.Quote(strings.ReplaceAll(exe, "%", "%%")) + " update-protected-recover " + strconv.Quote(strings.ReplaceAll(u.dataDir, "%", "%%")) + " " + id
	args := []string{"--quiet", "--no-block", "--collect", "--unit=yuhaiin-protected-update-" + id, "--property=Type=exec", "--property=RuntimeMaxSec=25h", "--property=ExecStopPost=:" + restart, exe, "update-protected-helper", u.dataDir, id}
	return servicehost.SystemdRun(ctx, args...)
}

type protectedUpdateService struct{ directory string }

func (protectedUpdateService) Stop(ctx context.Context) error {
	_, err := servicehost.Systemctl(ctx, "stop", "yuhaiin.service")
	return err
}
func (protectedUpdateService) Start(ctx context.Context) error {
	_, err := servicehost.Systemctl(ctx, "start", "yuhaiin.service")
	return err
}
func (protectedUpdateService) MainPID(ctx context.Context) (int, error) {
	out, err := servicehost.Systemctl(ctx, "show", "yuhaiin.service", "--property=MainPID", "--value")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}
