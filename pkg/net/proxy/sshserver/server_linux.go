//go:build linux && !android

package sshserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/yuhaiin/sessionnet"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

type Server struct {
	netapi.EmptyInterface
	listener  net.Listener
	addresses sessionnet.AddressConfig
	cgroups   *sessionnet.CgroupManager
	config    Config
	ssh       gossh.ServerConfig
	handler   netapi.Handler
	slots     chan struct{}
	clients   map[net.Conn]struct{}
	mu        sync.Mutex
	wg        sync.WaitGroup
	closeOnce sync.Once
	ctx       context.Context
	cancel    context.CancelFunc
}

var _ netapi.Accepter = (*Server)(nil)

// NewServer starts an SSH transport, but does not start any shell until its
// per-session network stack is ready. No host-routing fallback is permitted.
func NewServer(config Config, handler netapi.Handler) (*Server, error) {
	if handler == nil {
		return nil, errors.New("ssh inbound: nil handler")
	}
	signer, key, err := config.validate()
	if err != nil {
		return nil, err
	}
	addresses, err := config.resolveAddresses()
	if err != nil {
		return nil, err
	}
	cgroups, containment, err := selectContainment(config)
	if err != nil {
		return nil, err
	}
	// Refuse to listen when this host cannot create sessions, so the inbound
	// reports the cause instead of every login failing later.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err = sessionnet.Probe(ctx, sessionConfig(config, addresses, cgroups))
	cancel()
	if err != nil {
		if cgroups != nil {
			_ = cgroups.Close()
		}
		return nil, fmt.Errorf("ssh inbound (%s mode) cannot create isolated sessions: %w", config.NamespaceMode, err)
	}
	slog.Info("ssh inbound: isolated sessions ready", "mode", config.NamespaceMode,
		"uid", config.UID, "gid", config.GID, "containment", containment)
	server, err := newServerWithManager(config, handler, signer, key, addresses, cgroups)
	if err != nil && cgroups != nil {
		_ = cgroups.Close()
	}
	return server, err
}

// selectContainment chooses how descendant processes are contained. Every
// session has a PID namespace whose teardown kills all its processes; a
// cgroup v2 subtree is added when one is configured or delegated, which also
// lets a restarted Yuhaiin reap sessions orphaned by a crash. Rootful mode
// keeps its historical requirement of a cgroup.
func selectContainment(config Config) (*sessionnet.CgroupManager, string, error) {
	if config.CgroupRoot != "" {
		cgroups, err := sessionnet.NewCgroupManager(config.CgroupRoot)
		if err != nil {
			return nil, "", fmt.Errorf("ssh inbound: cgroupRoot %s must be a writable, delegated cgroup v2 directory: %w", config.CgroupRoot, err)
		}
		return cgroups, "cgroup v2 " + config.CgroupRoot, nil
	}
	if config.InboundID == "" {
		return nil, "", errors.New("ssh inbound: an inbound ID is required for cgroup recovery")
	}
	// Use a stable identity so the next process can reap orphaned sessions.
	sum := sha256.Sum256([]byte(config.InboundID))
	id := hex.EncodeToString(sum[:16])
	root := filepath.Join("/sys/fs/cgroup/yuhaiin/ssh", id)
	if config.NamespaceMode == NamespaceModeRootful {
		cgroups, err := sessionnet.NewCgroupManager(root)
		if err != nil {
			return nil, "", fmt.Errorf("ssh inbound: rootful mode requires cgroup v2 containment: %w", err)
		}
		return cgroups, "cgroup v2 " + root, nil
	}
	if os.Geteuid() == 0 {
		cgroups, err := sessionnet.NewCgroupManager(root)
		if err == nil {
			return cgroups, "cgroup v2 " + root, nil
		}
		slog.Warn("ssh inbound: cgroup v2 is unavailable, using the PID namespace supervisor", "reason", err.Error())
	} else if delegated, err := sessionnet.DelegatedCgroupRoot("yuhaiin-ssh-" + id); err == nil {
		cgroups, err := sessionnet.NewCgroupManager(delegated)
		if err == nil {
			return cgroups, "delegated cgroup v2 " + delegated, nil
		}
		slog.Warn("ssh inbound: delegated cgroup v2 is unusable, using the PID namespace supervisor", "reason", err.Error())
	}
	return nil, "PID namespace supervisor", nil
}

// sessionConfig describes the namespaces of one SSH transport.
func sessionConfig(config Config, addresses sessionnet.AddressConfig, cgroups *sessionnet.CgroupManager) sessionnet.Config {
	return sessionnet.Config{
		Mode:       config.sessionMode(),
		Credential: &sessionnet.Credential{UID: config.UID, GID: config.GID},
		MTU:        config.MTU, IPv6: config.IPv6,
		Addresses: addresses,
		Cgroup:    cgroups,
	}
}

// newServerWithManager binds and runs the SSH listener. Production callers
// always pass a verified manager; nil is reserved for isolated test fixtures.
func newServerWithManager(config Config, handler netapi.Handler, signer gossh.Signer, key gossh.PublicKey,
	addresses sessionnet.AddressConfig, cgroups *sessionnet.CgroupManager,
) (*Server, error) {
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return nil, fmt.Errorf("ssh inbound listen: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		listener: listener, config: config, handler: handler, addresses: addresses, cgroups: cgroups,
		slots: make(chan struct{}, config.MaxSessions), clients: make(map[net.Conn]struct{}),
		ctx: ctx, cancel: cancel,
	}
	server.ssh.PublicKeyCallback = func(metadata gossh.ConnMetadata, supplied gossh.PublicKey) (*gossh.Permissions, error) {
		if metadata.User() != config.Username ||
			subtle.ConstantTimeCompare(supplied.Marshal(), key.Marshal()) != 1 {
			return nil, errors.New("ssh inbound: unauthorized public key")
		}
		return &gossh.Permissions{}, nil
	}
	server.ssh.MaxAuthTries = 3
	server.ssh.AddHostKey(signer)
	server.wg.Add(1)
	go server.acceptLoop()
	return server, nil
}

func (s *Server) Interface() string { return "ssh" }

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.ctx.Err() != nil || len(s.clients) >= 32 {
			s.mu.Unlock()
			_ = conn.Close()
			continue
		}
		s.clients[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(raw net.Conn) {
	defer s.wg.Done()
	defer func() {
		_ = raw.Close()
		s.mu.Lock()
		delete(s.clients, raw)
		s.mu.Unlock()
	}()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	sshConn, chans, requests, err := gossh.NewServerConn(raw, &s.ssh)
	if err != nil {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	defer sshConn.Close()
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	network := &connectionNetwork{server: s, ctx: ctx}
	defer network.Close()
	go func() { _ = sshConn.Wait(); cancel() }()
	go gossh.DiscardRequests(requests)
	for {
		select {
		case <-ctx.Done():
			return
		case nc, ok := <-chans:
			if !ok {
				return
			}
			if nc.ChannelType() != "session" {
				_ = nc.Reject(gossh.UnknownChannelType, "only session channels are supported")
				continue
			}
			ch, requests, err := nc.Accept()
			if err != nil {
				continue
			}
			s.wg.Go(func() {
				s.handleSession(ctx, ch, requests, network)
			})
		}
	}
}

type ptyPair struct {
	master *os.File
	slave  *os.File
	term   string
}

func openPTY(columns, rows uint32) (*ptyPair, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		return nil, err
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		return nil, err
	}
	// A service may be a session leader without a controlling terminal.
	// Only the child should acquire this PTY; acquiring it here would prevent
	// the child from doing so and send SIGHUP to the server on PTY teardown.
	slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	master := os.NewFile(uintptr(fd), "ssh-pty")
	fd = -1
	p := &ptyPair{master: master, slave: slave}
	p.resize(columns, rows)
	return p, nil
}

func (p *ptyPair) resize(cols, rows uint32) {
	if p == nil || p.master == nil {
		return
	}
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	_ = unix.IoctlSetWinsize(int(p.master.Fd()), unix.TIOCSWINSZ,
		&unix.Winsize{Col: uint16(min(cols, 65535)), Row: uint16(min(rows, 65535))})
}

type ptyRequest struct {
	Term                         string
	Columns, Rows, Width, Height uint32
	Modes                        string
}
type execRequest struct{ Command string }
type subsystemRequest struct{ Name string }
type resizeRequest struct{ Columns, Rows, Width, Height uint32 }
type signalRequest struct{ Signal string }

var sshSignals = map[string]syscall.Signal{
	"ABRT": syscall.SIGABRT, "ALRM": syscall.SIGALRM, "FPE": syscall.SIGFPE, "HUP": syscall.SIGHUP,
	"ILL": syscall.SIGILL, "INT": syscall.SIGINT, "KILL": syscall.SIGKILL, "PIPE": syscall.SIGPIPE,
	"QUIT": syscall.SIGQUIT, "SEGV": syscall.SIGSEGV, "TERM": syscall.SIGTERM, "USR1": syscall.SIGUSR1,
	"USR2": syscall.SIGUSR2,
}

// processSlot holds the command a channel is running, for signal requests.
type processSlot struct {
	mu      sync.Mutex
	process *sessionnet.Process
}

func (p *processSlot) set(process *sessionnet.Process) {
	p.mu.Lock()
	p.process = process
	p.mu.Unlock()
}

func (p *processSlot) signal(sig syscall.Signal) {
	p.mu.Lock()
	process := p.process
	p.mu.Unlock()
	if process != nil {
		_ = process.Signal(sig)
	}
}

func (s *Server) handleSession(parent context.Context, ch gossh.Channel, requests <-chan *gossh.Request, network *connectionNetwork) {
	ctx, cancel := context.WithCancel(parent)
	var pty *ptyPair
	var done <-chan struct{}
	running := &processSlot{}
	defer func() {
		// The SSH channel must not finish until the launched process has
		// released its connection-scoped network and cgroup lease.
		cancel()
		if done != nil {
			<-done
		}
		if pty != nil {
			_ = pty.master.Close()
			_ = pty.slave.Close()
		}
		_ = ch.Close()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case req, ok := <-requests:
			if !ok {
				return
			}
			switch req.Type {
			case "pty-req":
				if done != nil || pty != nil {
					_ = req.Reply(false, nil)
					continue
				}
				var r ptyRequest
				if gossh.Unmarshal(req.Payload, &r) != nil || len(r.Term) > 128 || strings.ContainsAny(r.Term, "\x00\r\n") {
					_ = req.Reply(false, nil)
					continue
				}
				var err error
				pty, err = openPTY(r.Columns, r.Rows)
				if err == nil {
					pty.term = r.Term
				}
				_ = req.Reply(err == nil, nil)
			case "signal":
				// RFC 4254 section 6.9: forward to the running command only.
				var r signalRequest
				if gossh.Unmarshal(req.Payload, &r) == nil {
					if sig, ok := sshSignals[r.Signal]; ok {
						running.signal(sig)
					}
				}
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			case "window-change":
				var r resizeRequest
				if gossh.Unmarshal(req.Payload, &r) == nil && pty != nil {
					pty.resize(r.Columns, r.Rows)
				}
				_ = req.Reply(true, nil)
			case "shell", "exec", "subsystem":
				if done != nil {
					_ = req.Reply(false, nil)
					continue
				}
				args := []string{s.config.Shell, "-l"}
				if req.Type == "subsystem" {
					var r subsystemRequest
					if gossh.Unmarshal(req.Payload, &r) != nil || r.Name != "sftp" || pty != nil {
						_ = req.Reply(false, nil)
						continue
					}
					// Re-exec the running inode even if its installation directory
					// is private or the binary has been replaced by an update.
					args = append([]string{"/proc/self/exe", "internal-sftp"}, s.config.SFTPReadOnlyPaths...)
				} else if req.Type == "exec" {
					var r execRequest
					if gossh.Unmarshal(req.Payload, &r) != nil || len(r.Command) > 16384 {
						_ = req.Reply(false, nil)
						continue
					}
					args = []string{s.config.Shell, "-c", r.Command}
				} else if len(req.Payload) != 0 {
					_ = req.Reply(false, nil)
					continue
				}
				select {
				case s.slots <- struct{}{}:
				default:
					_ = req.Reply(false, nil)
					continue
				}
				doneCh := make(chan struct{})
				done = doneCh
				_ = req.Reply(true, nil)
				s.wg.Go(func() {
					defer close(doneCh)
					defer func() { <-s.slots }()
					s.execute(ctx, ch, args, pty, network, running)
				})
			default:
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (s *Server) execute(ctx context.Context, channel gossh.Channel, argv []string, pty *ptyPair, network *connectionNetwork, running *processSlot) {
	owner, err := network.acquire()
	if err != nil {
		// Setup errors are classified, user-facing explanations of the host
		// environment; never fall back to an unisolated shell.
		message := "unable to create the isolated session network"
		var setup *sessionnet.SetupError
		if errors.As(err, &setup) {
			message = setup.Message
			slog.Error("ssh inbound: isolated session setup failed", "stage", setup.Stage, "reason", setup.Error())
		} else if ctx.Err() == nil {
			slog.Error("ssh inbound: isolated session setup failed", "reason", err.Error())
		}
		_, _ = io.WriteString(channel.Stderr(), "ssh inbound: "+message+"\n")
		_ = sendExitStatus(channel, 255)
		return
	}
	// Complete the final lease release before acknowledging SSH exit status.
	release := sync.OnceFunc(network.release)
	defer release()

	home, username := sessionUser(s.config.UID, s.config.Username)
	config := sessionnet.Config{
		Command:    argv,
		Dir:        home,
		Env:        sessionEnvironment(s.config, home, username),
		Credential: &sessionnet.Credential{UID: s.config.UID, GID: s.config.GID},
	}
	// Match sshd's fallback when an account has no usable home directory.
	if info, err := os.Stat(home); err != nil || !info.IsDir() {
		config.Dir = "/"
	}
	var stdin, stdinWriter *os.File
	if pty != nil {
		config.PTYSlave = pty.slave
		if pty.term != "" {
			config.Env = append(config.Env, "TERM="+pty.term)
		}
	} else {
		// Pass stdin as a pipe so Wait does not depend on the client sending
		// EOF; interactive clients keep stdin open after the command exits.
		if stdin, stdinWriter, err = os.Pipe(); err != nil {
			_, _ = io.WriteString(channel.Stderr(), "ssh inbound: unable to start isolated command\n")
			release()
			_ = sendExitStatus(channel, 255)
			return
		}
		defer stdinWriter.Close()
		config.Stdin, config.Stdout, config.Stderr = stdin, channel, channel.Stderr()
	}
	process, err := owner.Spawn(ctx, config)
	if stdin != nil {
		_ = stdin.Close()
	}
	if err != nil {
		_, _ = io.WriteString(channel.Stderr(), "ssh inbound: unable to start isolated command\n")
		release()
		_ = sendExitStatus(channel, 255)
		return
	}
	defer process.Close()
	running.set(process)
	var output chan struct{}
	if pty != nil {
		output = make(chan struct{})
		go func() { _, _ = io.Copy(pty.master, channel) }()
		go func() { defer close(output); _, _ = io.Copy(channel, pty.master) }()
		_ = pty.slave.Close()
	} else {
		go func() { _, _ = io.Copy(stdinWriter, channel); _ = stdinWriter.Close() }()
	}
	err = process.Wait()
	if output != nil {
		// Drain buffered terminal output until the last slave descriptor
		// closes (EIO). Background jobs may hold the slave open, so bound it.
		select {
		case <-output:
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	running.set(nil)
	code := uint32(0)
	if err != nil {
		code = 255
		if exitErr, ok := errors.AsType[*sessionnet.ExitError](err); ok {
			if exitErr.Exited() {
				code = uint32(exitErr.ExitCode())
			} else {
				code = 128 + uint32(exitErr.Signal())
			}
		}
	}
	_ = process.Close()
	release()
	_ = sendExitStatus(channel, code)
}

// sessionEnvironment overrides only the child process timezone, leaving the
// host clock and the shared network namespace untouched.
func sessionEnvironment(config Config, home, username string) []string {
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + home,
		"USER=" + username, "LOGNAME=" + username,
		"SHELL=" + config.Shell,
	}
	if config.Timezone != "" {
		env = append(env, "TZ="+config.Timezone)
	}
	return env
}

func sessionUser(uid uint32, fallbackName string) (home, username string) {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "/", fallbackName
	}
	home = account.HomeDir
	if !filepath.IsAbs(home) {
		home = "/"
	}
	return home, account.Username
}
func sendExitStatus(ch gossh.Channel, code uint32) error {
	_, err := ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{code}))
	return err
}

// UpdateFakeIPRanges fails closed if a newly active pool would shadow the
// session gateway. Existing sessions are terminated before returning an error.
func (s *Server) UpdateFakeIPRanges(ranges [2]netip.Prefix) error {
	if err := checkFakeIPOverlap(s.addresses, ranges, s.config.IPv6); err != nil {
		_ = s.Close()
		return err
	}
	return nil
}

func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel()
		err = s.listener.Close()
		s.mu.Lock()
		for c := range s.clients {
			_ = c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
		if s.cgroups != nil {
			err = errors.Join(err, s.cgroups.Close())
		}
	})
	return err
}
