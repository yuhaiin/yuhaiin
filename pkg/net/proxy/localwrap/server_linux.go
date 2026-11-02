//go:build linux && !android

package localwrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/processnet"
	"github.com/yuhaiin/sessionnet"
	"golang.org/x/sys/unix"
)

type Server struct {
	config      Config
	listener    *net.UnixListener
	cgroups     *sessionnet.CgroupManager
	handler     netapi.Handler
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	clients     map[*net.UnixConn]struct{}
	pools       [2]netip.Prefix
	wg          sync.WaitGroup
	once        sync.Once
	closeErr    error
	unsubscribe func()
	// Tests can replace launch while retaining the real local protocol.
	launch func(context.Context, request, []*os.File, *sessionnet.Credential) (command, error)
}

type command interface {
	Wait() error
	Signal(os.Signal) error
	Close() error
}

func NewServer(config Config, handler netapi.Handler) (*Server, error) {
	if config.UID == 0 || config.GID == 0 || !filepath.IsAbs(config.Socket) || handler == nil {
		return nil, errors.New("wrap: absolute socket path, non-root UID/GID and inbound handler are required")
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = 8
	}
	if config.MaxSessions < 1 || config.MaxSessions > 128 {
		return nil, errors.New("wrap: max sessions must be 1..128")
	}
	if config.CgroupRoot == "" {
		config.CgroupRoot = fmt.Sprintf("/sys/fs/cgroup/yuhaiin/wrap/%x", sha256.Sum256([]byte(config.Socket)))
	}
	groups, err := sessionnet.NewCgroupManager(config.CgroupRoot)
	if err != nil {
		return nil, fmt.Errorf("wrap: cgroup v2 containment is required: %w", err)
	}
	s, err := listen(config, handler, groups, nil)
	if err != nil {
		_ = groups.Close()
		return nil, err
	}
	return s, nil
}

func listen(config Config, handler netapi.Handler, groups *sessionnet.CgroupManager, launch func(context.Context, request, []*os.File, *sessionnet.Credential) (command, error)) (*Server, error) {
	dir := filepath.Dir(config.Socket)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 || !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("wrap: socket parent must be owned by the service and not writable by other users")
	}
	if info, err := os.Lstat(config.Socket); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if info.Mode()&os.ModeSocket == 0 || !ok || stat.Uid != config.UID {
			return nil, errors.New("wrap: refusing to replace an unrelated socket path")
		}
		probe, err := net.DialTimeout("unix", config.Socket, 200*time.Millisecond)
		if err == nil {
			_ = probe.Close()
			return nil, errors.New("wrap: socket already has a live listener")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, err
		}
		if err := os.Remove(config.Socket); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.Socket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := errors.Join(os.Chmod(config.Socket, 0600), os.Chown(config.Socket, int(config.UID), int(config.GID))); err != nil {
		_ = listener.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{config: config, listener: listener, cgroups: groups, handler: handler, ctx: ctx, cancel: cancel, clients: make(map[*net.UnixConn]struct{})}
	s.launch = launch
	if s.launch == nil {
		s.launch = s.startCommand
	}
	if config.FakeIPSource != nil {
		s.unsubscribe, err = config.FakeIPSource.SubscribeFakeIPRanges(s.UpdateFakeIPRanges)
		if err != nil {
			cancel()
			_ = listener.Close()
			return nil, err
		}
	}
	s.wg.Go(s.accept)
	return s, nil
}

func (s *Server) accept() {
	for {
		c, err := s.listener.AcceptUnix()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.ctx.Err() != nil || len(s.clients) >= s.config.MaxSessions {
			s.mu.Unlock()
			_ = c.Close()
			continue
		}
		s.clients[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Go(func() {
			defer c.Close()
			defer func() { s.mu.Lock(); delete(s.clients, c); s.mu.Unlock() }()
			s.serve(c)
		})
	}
}

func peerCredential(c *net.UnixConn) (*sessionnet.Credential, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var credential *sessionnet.Credential
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		u, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		// SO_PEERGROUPS is a binary gid_t array, not a C string.
		groups := make([]uint32, 16)
		size := uint32(len(groups) * 4)
		readGroups := func() unix.Errno {
			_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_SOCKET, unix.SO_PEERGROUPS, uintptr(unsafe.Pointer(&groups[0])), uintptr(unsafe.Pointer(&size)), 0)
			return errno
		}
		errno := readGroups()
		if errno == unix.ERANGE && size <= 65536*4 && size%4 == 0 {
			groups = make([]uint32, size/4)
			errno = readGroups()
		}
		if errno != 0 {
			controlErr = errno
			return
		}
		if size%4 != 0 || size > uint32(len(groups)*4) {
			controlErr = errors.New("wrap: invalid peer groups")
			return
		}
		credential = &sessionnet.Credential{UID: u.Uid, GID: u.Gid, Groups: groups[:size/4]}
	})
	return credential, errors.Join(err, controlErr)
}

func (s *Server) serve(c *net.UnixConn) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	credential, err := peerCredential(c)
	if err != nil || credential.UID != s.config.UID || credential.GID == 0 {
		return
	}
	files, err := receiveFiles(c)
	if err != nil {
		return
	}
	defer closeFiles(files)
	var req request
	if err := readFrame(c, &req); err != nil {
		return
	}
	if err := req.validate(); err != nil {
		_ = writeFrame(c, message{Error: err.Error()})
		return
	}
	if (req.TTY && len(files) != 1) || (!req.TTY && len(files) != 3) {
		_ = writeFrame(c, message{Error: "wrap: descriptor count does not match terminal mode"})
		return
	}
	_ = c.SetDeadline(time.Time{})
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	// Read control messages during setup too: disconnect must cancel a
	// paused command rather than letting it run after its caller disappeared.
	signals := make(chan os.Signal, 16)
	go func() {
		defer cancel()
		for {
			var msg message
			if readFrame(c, &msg) != nil {
				return
			}
			if msg.Signal != int(syscall.SIGINT) && msg.Signal != int(syscall.SIGTERM) && msg.Signal != int(syscall.SIGHUP) && msg.Signal != int(syscall.SIGQUIT) {
				return
			}
			select {
			case signals <- syscall.Signal(msg.Signal):
			case <-ctx.Done():
				return
			}
		}
	}()
	process, err := s.launch(ctx, req, files, credential)
	if err != nil {
		_ = writeFrame(c, message{Error: "wrap: isolated command startup failed: " + err.Error()})
		return
	}
	defer process.Close()
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	var waitErr error
wait:
	for {
		select {
		case waitErr = <-done:
			break wait
		case signal := <-signals:
			_ = process.Signal(signal)
		case <-ctx.Done():
			_ = process.Close()
			return
		}
	}
	if err := process.Close(); err != nil {
		_ = writeFrame(c, message{Error: "wrap: session cleanup failed"})
		return
	}
	code := exitCode(waitErr)
	_ = writeFrame(c, message{Exit: &code})
}

type routedCommand struct {
	*sessionnet.Session
	link *processnet.Link
}

func (c *routedCommand) Close() error { return errors.Join(c.Session.Close(), c.link.Close()) }

func (s *Server) startCommand(ctx context.Context, req request, files []*os.File, credential *sessionnet.Credential) (command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := processnet.CheckFakeIPOverlap(sessionnet.AddressConfig{}, s.pools, s.config.IPv6); err != nil {
		return nil, err
	}
	cfg := sessionnet.Config{Command: req.Argv, Env: append([]string{}, req.Env...), Dir: req.Dir, Credential: credential, IPv6: s.config.IPv6, Cgroup: s.cgroups, IsolateDNS: true}
	if req.TTY {
		cfg.PTYSlave = files[0]
	} else {
		cfg.Stdin, cfg.Stdout, cfg.Stderr = files[0], files[1], files[2]
	}
	owner, err := sessionnet.Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	link, err := processnet.Attach(owner, s.handler, cfg.Addresses, cfg.MTU, cfg.IPv6, "wrap")
	if err != nil {
		_ = owner.Close()
		return nil, err
	}
	process := &routedCommand{Session: owner, link: link}
	if err := owner.Release(); err != nil {
		_ = process.Close()
		return nil, err
	}
	return process, nil
}

// UpdateFakeIPRanges blocks incompatible new sessions and terminates active
// sessions before an overlapping pool can shadow their DNS gateway.
func (s *Server) UpdateFakeIPRanges(pools [2]netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pools = pools
	if err := processnet.CheckFakeIPOverlap(sessionnet.AddressConfig{}, pools, s.config.IPv6); err != nil {
		for c := range s.clients {
			_ = c.Close()
		}
		return err
	}
	return nil
}

func (s *Server) Close() error {
	s.once.Do(func() {
		if s.unsubscribe != nil {
			s.unsubscribe()
		}
		s.cancel()
		s.closeErr = s.listener.Close()
		s.mu.Lock()
		for c := range s.clients {
			_ = c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
		if s.cgroups != nil {
			s.closeErr = errors.Join(s.closeErr, s.cgroups.Close())
		}
	})
	return s.closeErr
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if e, ok := errors.AsType[*exec.ExitError](err); ok {
		if status, ok := e.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return e.ExitCode()
	}
	return 125
}
