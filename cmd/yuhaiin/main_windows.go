package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func init() {
	if !isWindowsService() {
		return
	}

	log.OutputStderr = false
	wait = runService
}

func runService(lis net.Listener, errChan chan error, signChannel chan os.Signal) error {
	return svc.Run(version.AppName, &service{
		lis:         lis,
		errChan:     errChan,
		signChannel: signChannel,
	})
}

// copy from https://github.com/tailscale/tailscale/blob/main/cmd/tailscaled/install_windows.go

func install(args []string) (err error) {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows service manager: %v", err)
	}
	defer m.Disconnect()

	service, err := m.OpenService(version.AppName)
	if err == nil {
		service.Close()
		return fmt.Errorf("service %q is already installed", version.AppName)
	}

	// no such service; proceed to install the service.

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	c := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  version.AppName,
		Description:  "transparent proxy",
	}

	service, err = m.CreateService(version.AppName, exe, c, args...)
	if err != nil {
		return fmt.Errorf("failed to create %q service: %v", version.AppName, err)
	}
	defer service.Close()

	// Exponential backoff is often too aggressive, so use (mostly)
	// squares instead.
	ra := []mgr.RecoveryAction{
		{mgr.ServiceRestart, 1 * time.Second},
		{mgr.ServiceRestart, 2 * time.Second},
		{mgr.ServiceRestart, 4 * time.Second},
		{mgr.ServiceRestart, 9 * time.Second},
		{mgr.ServiceRestart, 16 * time.Second},
		{mgr.ServiceRestart, 25 * time.Second},
		{mgr.ServiceRestart, 36 * time.Second},
		{mgr.ServiceRestart, 49 * time.Second},
		{mgr.ServiceRestart, 64 * time.Second},
	}
	const resetPeriodSecs = 60
	err = service.SetRecoveryActions(ra, resetPeriodSecs)
	if err != nil {
		return fmt.Errorf("failed to set service recovery actions: %v", err)
	}

	return service.Start(args...)
}

func uninstall(args []string) (ret error) {
	// Remove file sharing from Windows shell (noop in non-windows)
	// osshare.SetFileSharingEnabled(false, logger.Discard)

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows service manager: %v", err)
	}
	defer m.Disconnect()

	service, err := m.OpenService(version.AppName)
	if err != nil {
		return fmt.Errorf("failed to open %q service: %v", version.AppName, err)
	}

	st, err := service.Query()
	if err != nil {
		service.Close()
		return fmt.Errorf("failed to query service state: %v", err)
	}
	if st.State != svc.Stopped {
		service.Control(svc.Stop)
	}
	err = service.Delete()
	service.Close()
	if err != nil {
		return fmt.Errorf("failed to delete service: %v", err)
	}

	end := time.Now().Add(15 * time.Second)
	for time.Until(end) > 0 {
		service, err = m.OpenService(version.AppName)
		if err != nil {
			// service is no longer openable; success!
			break
		}
		service.Close()
	}
	return nil
}

func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	if err != nil {
		log.Error("failed to check if we are running in Windows service", "err", err)
		panic(err)
	}

	return ok
}

type service struct {
	lis         net.Listener
	errChan     chan error
	signChannel chan os.Signal
}

func (ss *service) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {

	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case err := <-ss.errChan:
			log.Error("http server stop", "err", err)
			s <- svc.Status{State: svc.Stopped}
			return false, windows.NO_ERROR
		case <-ss.signChannel:
			ss.lis.Close()
			s <- svc.Status{State: svc.Stopped}
		case c := <-r:
			log.Info("Got Windows Service event", "cmd", cmdName(c.Cmd))
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				ss.lis.Close()
			}
		}
	}

}

func cmdName(c svc.Cmd) string {
	switch c {
	case svc.Stop:
		return "Stop"
	case svc.Pause:
		return "Pause"
	case svc.Continue:
		return "Continue"
	case svc.Interrogate:
		return "Interrogate"
	case svc.Shutdown:
		return "Shutdown"
	case svc.ParamChange:
		return "ParamChange"
	case svc.NetBindAdd:
		return "NetBindAdd"
	case svc.NetBindRemove:
		return "NetBindRemove"
	case svc.NetBindEnable:
		return "NetBindEnable"
	case svc.NetBindDisable:
		return "NetBindDisable"
	case svc.DeviceEvent:
		return "DeviceEvent"
	case svc.HardwareProfileChange:
		return "HardwareProfileChange"
	case svc.PowerEvent:
		return "PowerEvent"
	case svc.SessionChange:
		return "SessionChange"
	case svc.PreShutdown:
		return "PreShutdown"
	}
	return fmt.Sprintf("Unknown-Service-Cmd-%d", c)
}

func stop(args []string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(version.AppName)
	if err != nil {
		return err
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}

	timeDuration := time.Millisecond * 50

	timeout := time.After(getStopTimeout() + (timeDuration * 2))
	tick := time.NewTicker(timeDuration)
	defer tick.Stop()

	for status.State != svc.Stopped {
		select {
		case <-tick.C:
			status, err = s.Query()
			if err != nil {
				return err
			}
		case <-timeout:
			break
		}
	}

	return nil
}

func start(args []string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(version.AppName)
	if err != nil {
		return err
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return err
	}

	return nil
}

// getStopTimeout fetches the time before windows will kill the service.
func getStopTimeout() time.Duration {
	// For default and paths see https://support.microsoft.com/en-us/kb/146092
	defaultTimeout := time.Millisecond * 20000
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, registry.READ)
	if err != nil {
		return defaultTimeout
	}
	sv, _, err := key.GetStringValue("WaitToKillServiceTimeout")
	if err != nil {
		return defaultTimeout
	}
	v, err := strconv.Atoi(sv)
	if err != nil {
		return defaultTimeout
	}
	return time.Millisecond * time.Duration(v)
}

func restart(args []string) error {
	if err := stop(args); err != nil {
		return err
	}
	return start(args)
}
