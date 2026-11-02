//go:build linux && !android

package localwrap

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/yuhaiin/sessionnet"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

type testCommand struct {
	cmd    *exec.Cmd
	done   chan struct{}
	err    error
	once   sync.Once
	cancel context.CancelFunc
}

func (p *testCommand) Wait() error              { <-p.done; return p.err }
func (p *testCommand) Signal(s os.Signal) error { return p.cmd.Process.Signal(s) }
func (p *testCommand) Close() error             { p.once.Do(func() { p.cancel(); <-p.done }); return nil }

func launchTestCommand(ctx context.Context, req request, files []*os.File, _ *sessionnet.Credential) (command, error) {
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, req.Argv[0], req.Argv[1:]...)
	cmd.Env, cmd.Dir = req.Env, req.Dir
	if req.TTY {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = files[0], files[0], files[0]
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	} else {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = files[0], files[1], files[2]
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	p := &testCommand{cmd: cmd, done: make(chan struct{}), cancel: cancel}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	return p, nil
}

func testServer(t testing.TB, launch func(context.Context, request, []*os.File, *sessionnet.Credential) (command, error)) *Server {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("local protocol tests use a non-root peer")
	}
	config := Config{Socket: filepath.Join(t.TempDir(), "wrap.sock"), UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), MaxSessions: 8}
	server, err := listen(config, nil, nil, launch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	return server
}

func testFiles(t testing.TB) (*os.File, *os.File, *os.File) {
	t.Helper()
	files := make([]*os.File, 3)
	for i := range files {
		var err error
		files[i], err = os.CreateTemp(t.TempDir(), "stdio")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = files[i].Close() })
	}
	return files[0], files[1], files[2]
}

func TestRunPreservesLocalLaunchAndExitStatus(t *testing.T) {
	seen := make(chan *sessionnet.Credential, 1)
	server := testServer(t, func(ctx context.Context, req request, files []*os.File, credential *sessionnet.Credential) (command, error) {
		seen <- credential
		return launchTestCommand(ctx, req, files, credential)
	})
	stdin, stdout, stderr := testFiles(t)
	dir := t.TempDir()
	args := []string{"/bin/sh", "-c", `printf '%s\n' "$PWD" "$VALUE" "$1" "$2"; cat; printf 'stderr-output' >&2; exit 37`, "wrap-test", "", "a b ' $(literal)"}
	if _, err := stdin.WriteString("stdin-payload"); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	code, err := Run(t.Context(), Options{Socket: server.config.Socket, Argv: args, Env: []string{"VALUE=local-value", "PATH=/usr/bin:/bin"}, Dir: dir, Stdin: stdin, Stdout: stdout, Stderr: stderr})
	if err != nil || code != 37 {
		t.Fatalf("exit %d: %v", code, err)
	}
	out, err := os.ReadFile(stdout.Name())
	if err != nil {
		t.Fatal(err)
	}
	if want := dir + "\nlocal-value\n\na b ' $(literal)\nstdin-payload"; string(out) != want {
		t.Fatalf("stdout %q, want %q", out, want)
	}
	out, err = os.ReadFile(stderr.Name())
	if err != nil || string(out) != "stderr-output" {
		t.Fatalf("stderr %q %v", out, err)
	}
	peer := <-seen
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	var expected []uint32
	for _, gid := range groups {
		expected = append(expected, uint32(gid))
	}
	if peer.UID != uint32(os.Getuid()) || peer.GID != uint32(os.Getgid()) || !slices.Equal(peer.Groups, expected) {
		t.Fatalf("peer credentials %#v, groups %v", peer, expected)
	}
}

func TestDisconnectCancelsLaunchInProgress(t *testing.T) {
	started, canceled := make(chan struct{}), make(chan struct{})
	server := testServer(t, func(ctx context.Context, _ request, _ []*os.File, _ *sessionnet.Credential) (command, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	stdin, stdout, stderr := testFiles(t)
	go func() {
		defer close(done)
		_, _ = Run(ctx, Options{Socket: server.config.Socket, Argv: []string{"/bin/true"}, Stdin: stdin, Stdout: stdout, Stderr: stderr})
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("launch did not start")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("disconnected launch was not canceled")
	}
	<-done
}

func TestStartupFailureIsReportedWithoutFallback(t *testing.T) {
	server := testServer(t, func(context.Context, request, []*os.File, *sessionnet.Credential) (command, error) {
		return nil, errors.New("injected namespace failure")
	})
	stdin, stdout, stderr := testFiles(t)
	code, err := Run(t.Context(), Options{Socket: server.config.Socket, Argv: []string{"/bin/true"}, Stdin: stdin, Stdout: stdout, Stderr: stderr})
	if code != 125 || err == nil {
		t.Fatalf("startup failure: %d %v", code, err)
	}
}

func TestServerRefusesUnmanagedCgroupAndRootAccount(t *testing.T) {
	for _, uid := range []uint32{0, 65534} {
		_, err := NewServer(Config{Socket: filepath.Join(t.TempDir(), "wrap.sock"), UID: uid, GID: 65534, CgroupRoot: t.TempDir()}, &discardHandler{})
		if err == nil {
			t.Fatal("unsafe server configuration accepted")
		}
	}
}

type discardHandler struct{}

func (*discardHandler) HandleStream(m *netapi.StreamMeta) { _ = m.Src.Close() }
func (*discardHandler) HandlePacket(*netapi.Packet)       {}
func (*discardHandler) HandlePing(*netapi.PingMeta)       {}

func TestSocketOwnershipAndExistingFileProtection(t *testing.T) {
	server := testServer(t, launchTestCommand)
	info, err := os.Stat(server.config.Socket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions %v %v", info, err)
	}
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(Config{Socket: path, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}, nil, nil, launchTestCommand); err == nil {
		t.Fatal("existing file replaced")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "keep" {
		t.Fatal("existing file changed")
	}
}

func TestOverlappingFakeIPDisconnectsActiveSession(t *testing.T) {
	started := make(chan struct{})
	server := testServer(t, func(ctx context.Context, _ request, _ []*os.File, _ *sessionnet.Credential) (command, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	stdin, stdout, stderr := testFiles(t)
	done := make(chan error, 1)
	go func() {
		_, err := Run(t.Context(), Options{Socket: server.config.Socket, Argv: []string{"/bin/true"}, Stdin: stdin, Stdout: stdout, Stderr: stderr})
		done <- err
	}()
	<-started
	if err := server.UpdateFakeIPRanges([2]netip.Prefix{netip.MustParsePrefix("172.31.254.0/24")}); err == nil {
		t.Fatal("overlap accepted")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("overlap did not disconnect client")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("overlap hung")
	}
}

type initialFakeIPSource struct{ pools [2]netip.Prefix }

func (s initialFakeIPSource) SubscribeFakeIPRanges(update func([2]netip.Prefix) error) (func(), error) {
	if err := update(s.pools); err != nil {
		return nil, err
	}
	return func() {}, nil
}

func TestInitialFakeIPOverlapRejectsListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrap.sock")
	_, err := listen(Config{Socket: path, UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), FakeIPSource: initialFakeIPSource{pools: [2]netip.Prefix{netip.MustParsePrefix("172.31.254.0/24")}}}, nil, nil, launchTestCommand)
	if err == nil {
		t.Fatal("listener accepted overlapping initial FakeIP ranges")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("failed listener left a socket: %v", err)
	}
}

func TestExitCodePreservesSignalTermination(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "kill -TERM $$")
	if got := exitCode(cmd.Run()); got != 143 {
		t.Fatalf("got %d, want 143", got)
	}
}

func TestControlSignalReachesRunningCommand(t *testing.T) {
	started := make(chan struct{})
	server := testServer(t, func(ctx context.Context, req request, files []*os.File, credential *sessionnet.Credential) (command, error) {
		process, err := launchTestCommand(ctx, req, files, credential)
		close(started)
		return process, err
	})
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: server.config.Socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	stdin, stdout, stderr := testFiles(t)
	if err := sendFiles(c, []*os.File{stdin, stdout, stderr}); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(c, request{Version: protocolVersion, Argv: []string{"/bin/sleep", "30"}, Dir: "/", Env: []string{}}); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := writeFrame(c, message{Signal: int(syscall.SIGTERM)}); err != nil {
		t.Fatal(err)
	}
	var response message
	if err := readFrame(c, &response); err != nil || response.Exit == nil || *response.Exit != 143 {
		t.Fatalf("signal response: %+v %v", response, err)
	}
}

func TestTerminalInputWindowSizeAndRestoration(t *testing.T) {
	server := testServer(t, launchTestCommand)
	master, terminal, err := openPTY()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 33, Col: 110}); err != nil {
		t.Fatal(err)
	}
	before, err := term.GetState(int(terminal.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_, stdout, stderr := testFiles(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go func() { time.Sleep(50 * time.Millisecond); _, _ = master.WriteString("terminal-input\n") }()
	code, err := Run(ctx, Options{Socket: server.config.Socket, Argv: []string{"/bin/sh", "-c", `test -t 0 && test -t 1 && stty size; read -r line; printf 'received:%s\n' "$line"`}, Stdin: terminal, Stdout: stdout, Stderr: stderr, Terminal: true})
	if err != nil || code != 0 {
		t.Fatalf("terminal command: %d %v", code, err)
	}
	after, err := term.GetState(int(terminal.Fd()))
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("terminal state not restored: %v", err)
	}
	output, err := os.ReadFile(stdout.Name())
	if err != nil || !strings.Contains(string(output), "33 110") || !strings.Contains(string(output), "received:terminal-input") {
		t.Fatalf("terminal output %q: %v", output, err)
	}
}

func TestPeerIdentityCannotBeOverriddenInRequest(t *testing.T) {
	c, peer := socketPair(t)
	server := &Server{config: Config{UID: uint32(os.Getuid()) + 1}}
	done := make(chan struct{})
	go func() { defer close(done); defer peer.Close(); server.serve(peer) }()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := c.Read(b[:]); err == nil {
		t.Fatal("unauthorized peer accepted")
	}
	<-done
}

func BenchmarkLocalCommand(b *testing.B) {
	server := testServer(b, launchTestCommand)
	stdin, stdout, stderr := testFiles(b)
	options := Options{Socket: server.config.Socket, Argv: []string{"/bin/true"}, Stdin: stdin, Stdout: stdout, Stderr: stderr}
	b.ReportAllocs()
	for b.Loop() {
		if code, err := Run(b.Context(), options); err != nil || code != 0 {
			b.Fatalf("exit %d: %v", code, err)
		}
	}
}
