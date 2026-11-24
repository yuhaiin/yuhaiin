//go:build linux && !android

package sshserver

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/yuhaiin/sessionnet"
)

// Host filesystem identity. A rootless SSH shell must access the host
// filesystem as the host account it is configured for, also when Yuhaiin
// runs inside a user namespace (`podman unshare`, where that account is UID
// 0 of Yuhaiin's namespace). Run it there with, for example:
//
//	podman unshare env YUH_SSH_TEST_HOME=$HOME YUH_SSH_TEST_UID=$(id -u) \
//	    YUH_SSH_TEST_GID=$(id -g) ./sshserver.test -test.run FilesystemIdentity -test.v
//
// YUH_SSH_TEST_HOME names a host directory owned by the account (default: a
// temporary directory); YUH_SSH_TEST_UID/GID are the expected host IDs
// (default: what sessionnet resolves). YUH_SSH_TEST_DENIED_DIR optionally
// names a directory the account must not read, and YUH_SSH_TEST_GROUP_DIR one
// it may use only through a supplementary group.
func TestSSHServerHostFilesystemIdentity(t *testing.T) {
	requireSSHSessionIntegration(t)
	if testHostRoot() {
		t.Skip("host root runs rootless shells as an explicit account; covered by the default-identity tests")
	}
	own := testOwnIdentity(t)
	want := own
	if v := os.Getenv("YUH_SSH_TEST_UID"); v != "" {
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		want.UID = uint32(id)
	}
	if v := os.Getenv("YUH_SSH_TEST_GID"); v != "" {
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		want.GID = uint32(id)
	}
	if want.UID != own.UID || want.GID != own.GID {
		t.Fatalf("sessionnet resolves Yuhaiin's host identity to %d:%d, expected %d:%d", own.UID, own.GID, want.UID, want.GID)
	}
	home := os.Getenv("YUH_SSH_TEST_HOME")
	if home == "" {
		home = t.TempDir()
	}
	var before syscall.Stat_t
	if err := syscall.Stat(home, &before); err != nil {
		t.Fatal(err)
	}

	// The configuration that used to fail: the host IDs set explicitly.
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit=%v", explicit), func(t *testing.T) {
			config, signer := newSSHServerTestIdentity(t)
			config.InboundID = fmt.Sprintf("identity-%v", explicit)
			if explicit {
				config.UID, config.GID = want.UID, want.GID
			}
			server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
			if server.config.UID != want.UID || server.config.GID != want.GID {
				t.Fatalf("configured identity %d:%d, want %d:%d", server.config.UID, server.config.GID, want.UID, want.GID)
			}
			client := dialSSHServer(t, server, config.Username, signer)
			script := fmt.Sprintf(`echo "id=$(id -u):$(id -g)"
echo "owner=$(stat -c '%%u:%%g %%U:%%G' %[1]s)"
cd %[1]s && echo "cd=ok"
touch permission-test && echo "touch=ok"
echo "created=$(stat -c %%u:%%g permission-test)"
cat permission-test && echo "cat=ok"
rm permission-test && echo "rm=ok"
`, home)
			if dir := os.Getenv("YUH_SSH_TEST_DENIED_DIR"); dir != "" {
				script += fmt.Sprintf("ls %s >/dev/null 2>&1 && echo denied=no || echo denied=yes\n", dir)
			}
			if dir := os.Getenv("YUH_SSH_TEST_GROUP_DIR"); dir != "" {
				script += fmt.Sprintf("touch %[1]s/probe-$$ && rm %[1]s/probe-$$ && echo groupaccess=yes || echo groupaccess=no\n", dir)
			}
			out := string(runSSHCommand(t, client, script))
			t.Logf("ssh output:\n%s", out)
			ids := fmt.Sprintf("%d:%d", want.UID, want.GID)
			names := ids
			if account, err := user.LookupId(strconv.FormatUint(uint64(want.UID), 10)); err == nil {
				names = account.Username
				if group, err := user.LookupGroupId(strconv.FormatUint(uint64(want.GID), 10)); err == nil {
					names += ":" + group.Name
				}
			}
			for _, line := range []string{"id=" + ids, "owner=" + ids + " " + names, "cd=ok", "touch=ok", "created=" + ids, "cat=ok", "rm=ok"} {
				if !strings.Contains(out, line+"\n") {
					t.Errorf("ssh output lacks %q", line)
				}
			}
			if os.Getenv("YUH_SSH_TEST_DENIED_DIR") != "" && !strings.Contains(out, "denied=yes") {
				t.Error("the shell could read a directory of another account")
			}
			if os.Getenv("YUH_SSH_TEST_GROUP_DIR") != "" && !strings.Contains(out, "groupaccess=yes") {
				t.Error("the shell lost the access of a supplementary group")
			}
		})
	}
	var after syscall.Stat_t
	if err := syscall.Stat(home, &after); err != nil {
		t.Fatal(err)
	}
	if after.Uid != before.Uid || after.Gid != before.Gid || after.Mode != before.Mode {
		t.Fatalf("home ownership changed from %d:%d %o to %d:%d %o", before.Uid, before.Gid, before.Mode, after.Uid, after.Gid, after.Mode)
	}
	if _, err := os.Stat(filepath.Join(home, "permission-test")); !os.IsNotExist(err) {
		t.Fatalf("permission-test was left behind: %v", err)
	}
}

func TestDetectEnvironment(t *testing.T) {
	requireSSHSessionIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := DetectEnvironment(ctx)
	t.Logf("environment: %+v session %+v", env, env.Session)
	ns, err := sessionnet.CurrentUserNamespace()
	if err != nil {
		t.Fatal(err)
	}
	wantOrigin := "inherited"
	if ns.Initial {
		wantOrigin = "host"
	}
	if env.UserNamespace.Origin != wantOrigin || env.UserNamespace.Depth != ns.Depth || !env.UserNamespace.NestedUserNamespaceSupported {
		t.Fatalf("user namespace %+v", env.UserNamespace)
	}
	if env.Error != "" || env.Session == nil || !env.Session.FilesystemIdentityPreserved {
		t.Fatalf("probe session: %q %+v", env.Error, env.Session)
	}
	for name, status := range map[string]string{"user": env.Features.UserNamespace, "net": env.Features.NetworkNamespace,
		"mnt": env.Features.MountNamespace, "pid": env.Features.PIDNamespace, "idmap": env.Features.IDMapping,
		"tun": env.Features.TUN, "ipv4": env.Features.IPv4, "ipv6": env.Features.IPv6, "supervisor": env.Features.Supervisor} {
		if status != contract.SSHFeatureAvailable {
			t.Errorf("feature %s is %q", name, status)
		}
	}
	own := testOwnIdentity(t)
	if env.Session.UID != own.UID || env.Session.GID != own.GID || env.Identity.NamespaceUID != uint32(os.Geteuid()) ||
		env.Session.NamespaceUID != uint32(os.Geteuid()) {
		t.Fatalf("identity %+v session %+v, want host %d:%d", env.Identity, env.Session, own.UID, own.GID)
	}
	if ns.HostIDs() && (env.Identity.HostUID == nil || *env.Identity.HostUID != own.UID) {
		t.Fatalf("host UID %v, want %d", env.Identity.HostUID, own.UID)
	}
	// A second call within the TTL is served from the cache.
	again := DetectEnvironment(ctx)
	if again.CheckedAt != env.CheckedAt {
		t.Fatal("detection was not cached")
	}
}
