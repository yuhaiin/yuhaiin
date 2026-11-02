//go:build linux && !android

package localwrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Run connects to the local service and returns the command's shell-compatible
// exit code. A setup or protocol failure returns 125 and an explanatory error.
func Run(ctx context.Context, options Options) (code int, runErr error) {
	if len(options.Argv) == 0 {
		return 125, errors.New("wrap: a program is required")
	}
	if options.Socket == "" {
		options.Socket = DefaultSocket
	}
	if options.Stdin == nil {
		options.Stdin = os.Stdin
	}
	if options.Stdout == nil {
		options.Stdout = os.Stdout
	}
	if options.Stderr == nil {
		options.Stderr = os.Stderr
	}
	if options.Env == nil {
		options.Env = os.Environ()
	}
	if options.Dir == "" {
		var err error
		options.Dir, err = os.Getwd()
		if err != nil {
			return 125, err
		}
	}
	argv := slices.Clone(options.Argv)
	program, err := exec.LookPath(argv[0])
	if err != nil {
		return 127, err
	}
	argv[0], err = filepath.Abs(program)
	if err != nil {
		return 125, err
	}
	req := request{Version: protocolVersion, Argv: argv, Env: options.Env, Dir: options.Dir, TTY: options.Terminal}
	if err := req.validate(); err != nil {
		return 125, err
	}
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(ctx, "unix", options.Socket)
	if err != nil {
		return 125, fmt.Errorf("wrap: connect to local service: %w", err)
	}
	c := raw.(*net.UnixConn)
	defer c.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	files := []*os.File{options.Stdin, options.Stdout, options.Stderr}
	var master, slave *os.File
	if req.TTY {
		master, slave, err = openPTY()
		if err != nil {
			return 125, err
		}
		defer master.Close()
		defer slave.Close()
		resizePTY(master, options.Stdin)
		files = []*os.File{slave}
	}
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := sendFiles(c, files); err != nil {
		return 125, err
	}
	if err := writeFrame(c, req); err != nil {
		return 125, err
	}
	_ = c.SetWriteDeadline(time.Time{})
	var output chan struct{}
	if req.TTY {
		state, err := term.MakeRaw(int(options.Stdin.Fd()))
		if err != nil {
			return 125, err
		}
		defer func() {
			if err := term.Restore(int(options.Stdin.Fd()), state); err != nil {
				code = 125
				runErr = errors.Join(runErr, fmt.Errorf("wrap: restore terminal: %w", err))
			}
		}()
		resizePTY(master, options.Stdin)
		_ = slave.Close()
		output = make(chan struct{})
		go func() { defer close(output); _, _ = io.Copy(options.Stdout, master) }()
		inputDone := make(chan struct{})
		go func() { defer close(inputDone); relayInput(ctx, master, options.Stdin) }()
		defer func() { cancel(); _ = master.Close(); <-inputDone }()
	}
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGWINCH)
	defer signal.Stop(signals)
	type response struct {
		msg message
		err error
	}
	responses := make(chan response, 1)
	go func() { var msg message; err := readFrame(c, &msg); responses <- response{msg, err} }()
	for {
		select {
		case res := <-responses:
			if res.err != nil {
				return 125, fmt.Errorf("wrap: local session disconnected: %w", res.err)
			}
			if res.msg.Error != "" {
				return 125, errors.New(res.msg.Error)
			}
			if res.msg.Exit == nil || *res.msg.Exit < 0 || *res.msg.Exit > 255 {
				return 125, errors.New("wrap: invalid exit status")
			}
			if output != nil {
				select {
				case <-output:
				case <-time.After(2 * time.Second):
				case <-ctx.Done():
				}
			}
			return *res.msg.Exit, nil
		case sig := <-signals:
			if sig == syscall.SIGWINCH {
				if master != nil {
					resizePTY(master, options.Stdin)
				}
				continue
			}
			_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if err := writeFrame(c, message{Signal: int(sig.(syscall.Signal))}); err != nil {
				return 125, err
			}
			_ = c.SetWriteDeadline(time.Time{})
		case <-ctx.Done():
			return 125, ctx.Err()
		}
	}
}

func openPTY() (_ *os.File, _ *os.File, err error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	master := os.NewFile(uintptr(fd), "wrap-pty")
	defer func() {
		if err != nil {
			_ = master.Close()
		}
	}()
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		return nil, nil, err
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		return nil, nil, err
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	return master, slave, nil
}

func resizePTY(master, terminal *os.File) {
	size, err := unix.IoctlGetWinsize(int(terminal.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return
	}
	raw, err := master.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) { _ = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, size) })
}

func relayInput(ctx context.Context, master, input *os.File) {
	poll := []unix.PollFd{{Fd: int32(input.Fd()), Events: unix.POLLIN}}
	buf := make([]byte, 4096)
	for ctx.Err() == nil {
		n, err := unix.Poll(poll, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		n, err = unix.Read(int(input.Fd()), buf)
		if err != nil || n == 0 {
			return
		}
		if _, err := master.Write(buf[:n]); err != nil {
			return
		}
	}
}
