package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The real startup owns global application state, so exercise it in subprocesses.
func TestInitializationCodeActualStartup(t *testing.T) {
	const directoryEnv = "YUH_TEST_INITIALIZATION_DIRECTORY"
	const modeEnv = "YUH_TEST_INITIALIZATION_MODE"
	const codeEnv = "YUHAIIN_INITIALIZATION_CODE"
	environmentCode := "ys_" + strings.Repeat("A", 43)
	argumentCode := "ys_" + strings.Repeat("B", 42) + "A"
	if directory := os.Getenv(directoryEnv); directory != "" {
		mode := os.Getenv(modeEnv)
		args := []string{"-path", directory, "-host", "127.0.0.1:0", "-https=false"}
		expected := environmentCode
		if mode == "override" {
			args = append(args, "-initialization-code", argumentCode)
			expected = argumentCode
		}
		wait = func(ctx context.Context, listeners ...net.Listener) error {
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+listeners[0].Addr().String()+"/api/v2/auth/setup/parameters", strings.NewReader("{}"))
			if err != nil {
				return err
			}
			request.Header.Set("Authorization", "Setup "+expected)
			client := &http.Client{Timeout: 5 * time.Second}
			response, err := client.Do(request)
			if err != nil {
				return err
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				return errors.New("actual startup did not accept the configured initialization code")
			}
			return nil
		}
		err := run(args)
		if mode == "invalid" {
			if err == nil || !strings.Contains(err.Error(), "invalid initialization code") {
				t.Fatal("invalid configured code did not abort startup")
			}
			if strings.Contains(err.Error(), os.Getenv(codeEnv)) {
				t.Fatal("startup error exposed the configured code")
			}
		} else if err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, mode := range []string{"environment", "override", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv(codeEnv, environmentCode)
			if mode == "invalid" {
				t.Setenv(codeEnv, "invalid-private-code")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInitializationCodeActualStartup$", "-test.count=1")
			command.Env = append(os.Environ(), directoryEnv+"="+t.TempDir(), modeEnv+"="+mode)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("startup failed: %v\n%s", err, output)
			}
			for _, secret := range []string{environmentCode, argumentCode, "invalid-private-code"} {
				if bytes.Contains(output, []byte(secret)) {
					t.Fatal("actual startup output exposed a configured code")
				}
			}
		})
	}
}

func TestInitializationCodePrecedenceAndHelp(t *testing.T) {
	const environment = "YUHAIIN_INITIALIZATION_CODE"
	for _, tt := range []struct {
		name string
		env  *string
		args []string
		want *string
	}{
		{name: "random"},
		{name: "environment", env: new("environment-secret"), want: new("environment-secret")},
		{name: "CLI", args: []string{"-initialization-code", "argument-secret"}, want: new("argument-secret")},
		{name: "CLI overrides environment", env: new("environment-secret"), args: []string{"-initialization-code=argument-secret"}, want: new("argument-secret")},
		{name: "empty environment is explicit", env: new(""), want: new("")},
		{name: "empty CLI overrides environment", env: new("environment-secret"), args: []string{"-initialization-code="}, want: new("")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(environment, "")
			if tt.env == nil {
				if err := os.Unsetenv(environment); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Setenv(environment, *tt.env)
			}
			flags := flag.NewFlagSet("test", flag.ContinueOnError)
			options := initializationOptions(flags)
			if err := flags.Parse(tt.args); err != nil {
				t.Fatal(err)
			}
			got := options.InitializationCode
			if (got == nil) != (tt.want == nil) || got != nil && *got != *tt.want {
				t.Fatal("wrong initialization code source")
			}
			var output bytes.Buffer
			flags.SetOutput(&output)
			flags.PrintDefaults()
			if err := flags.Parse([]string{"-h"}); !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("help error: %v", err)
			}
			for _, secret := range []string{"environment-secret", "argument-secret"} {
				if strings.Contains(output.String(), secret) {
					t.Fatal("help exposed an initialization secret")
				}
			}
		})
	}
}
