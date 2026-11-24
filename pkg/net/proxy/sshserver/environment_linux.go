//go:build linux && !android

package sshserver

import (
	"context"
	"os"
	"sync"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/yuhaiin/sessionnet"
	"golang.org/x/sys/unix"
)

// environmentTTL bounds how long a detection result is reused. The user
// namespace never changes for a running process, but features such as
// cgroup delegation or /dev/net/tun access can.
const environmentTTL = 30 * time.Second

var environmentCache struct {
	mu      sync.Mutex
	value   contract.SSHEnvironment
	expires time.Time
	running chan struct{}
}

// DetectEnvironment reports the user namespace Yuhaiin runs in, the
// identity rootless SSH sessions get by default and what a short-lived probe
// session could set up. Concurrent callers share one probe, and results are
// reused for environmentTTL.
func DetectEnvironment(ctx context.Context) contract.SSHEnvironment {
	c := &environmentCache
	for {
		c.mu.Lock()
		if time.Now().Before(c.expires) {
			value := c.value
			c.mu.Unlock()
			return value
		}
		if running := c.running; running != nil {
			c.mu.Unlock()
			select {
			case <-running:
				continue
			case <-ctx.Done():
				return contract.SSHEnvironment{Error: ctx.Err().Error(), Features: unknownFeatures()}
			}
		}
		running := make(chan struct{})
		c.running = running
		c.mu.Unlock()

		// The probe outlives a canceled request so that waiters get a result.
		probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		value := detectEnvironment(probeCtx)
		cancel()
		c.mu.Lock()
		c.value, c.expires, c.running = value, time.Now().Add(environmentTTL), nil
		c.mu.Unlock()
		close(running)
		return value
	}
}

func unknownFeatures() contract.SSHFeatures {
	u := contract.SSHFeatureUnknown
	return contract.SSHFeatures{UserNamespace: u, NetworkNamespace: u, MountNamespace: u, PIDNamespace: u,
		IDMapping: u, TUN: u, IPv4: u, IPv6: u, Supervisor: u, CgroupV2: u, Rootful: u}
}

func detectEnvironment(ctx context.Context) contract.SSHEnvironment {
	report := sessionnet.Inspect(ctx, sessionnet.Config{Mode: sessionnet.ModeRootless, IPv6: true})
	env := contract.SSHEnvironment{CheckedAt: time.Now().UTC().Format(time.RFC3339), Features: unknownFeatures()}
	if ns := report.Namespace; ns != nil {
		env.UserNamespace = contract.SSHUserNamespace{
			Origin: "inherited", Depth: ns.Depth, DepthError: ns.DepthError, HostIDsResolved: ns.HostIDs(),
			UIDMap: idMappings(ns.UIDMap), GIDMap: idMappings(ns.GIDMap), SetgroupsAllowed: ns.SetgroupsAllowed,
		}
		if ns.Initial {
			env.UserNamespace.Origin = "host"
		}
	} else {
		env.UserNamespace = contract.SSHUserNamespace{Origin: "unknown", Depth: -1, DepthError: report.NamespaceError}
	}
	caller := report.Caller
	env.Identity = contract.SSHIdentity{
		HostUID: report.HostUID, HostGID: report.HostGID, NamespaceUID: caller.UID, NamespaceGID: caller.GID,
		UIDRanges: idRanges(report.UIDRanges), GIDRanges: idRanges(report.GIDRanges),
		CapSetUID: caller.CapSetUID, CapSetGID: caller.CapSetGID, CapSetFCAP: caller.CapSetFCAP,
		CapSysAdmin: caller.CapSysAdm, CapNetAdmin: caller.CapNetAdm, Groups: []contract.SSHGroup{},
	}
	for _, g := range report.Groups {
		group := contract.SSHGroup{NamespaceGID: g.ID}
		if g.HostMapped {
			group.HostGID = new(g.HostID)
		}
		env.Identity.Groups = append(env.Identity.Groups, group)
	}
	f := report.Features
	env.Features.UserNamespace, env.Features.NetworkNamespace = string(f.UserNamespace), string(f.NetworkNamespace)
	env.Features.MountNamespace, env.Features.PIDNamespace = string(f.MountNamespace), string(f.PIDNamespace)
	env.Features.IDMapping, env.Features.TUN = string(f.IDMapping), string(f.TUN)
	env.Features.IPv4, env.Features.IPv6, env.Features.Supervisor = string(f.IPv4), string(f.IPv6), string(f.Supervisor)
	env.UserNamespace.NestedUserNamespaceSupported = f.UserNamespace == sessionnet.FeatureAvailable
	env.Features.CgroupV2 = cgroupAvailability()
	env.Features.Rootful = contract.SSHFeatureUnavailable
	if report.Namespace != nil && report.Namespace.Initial && caller.UID == 0 && caller.CapSysAdm && caller.CapNetAdm {
		env.Features.Rootful = contract.SSHFeatureAvailable
	}
	if s := report.Session; s != nil {
		home, username := sessionUser(s.Credential.UID, "")
		env.Session = &contract.SSHSessionIdentity{
			UID: s.Credential.UID, GID: s.Credential.GID, NamespaceUID: s.CallerUID, NamespaceGID: s.CallerGID,
			UIDMap: idMappings(s.UIDMap), GIDMap: idMappings(s.GIDMap),
			SupplementaryGroupsInherited: report.InheritsGroups,
			SupplementaryGroupsSettable:  report.Namespace != nil && report.Namespace.SetgroupsAllowed && caller.CapSetGID,
			FilesystemIdentityPreserved:  report.IdentityVerified,
			Username:                     username, Home: home, Shell: loginShell(s.Credential.UID),
		}
	}
	if report.Error != nil {
		env.Error, env.ErrorStage = report.Error.Message, string(report.Error.Stage)
	}
	return env
}

// cgroupAvailability mirrors selectContainment for rootless sessions
// without creating anything: host root may use /sys/fs/cgroup/yuhaiin, a
// normal user (or root of a nested namespace) needs a delegated subtree.
func cgroupAvailability() string {
	if hostRoot() {
		dir := "/sys/fs/cgroup/yuhaiin"
		if _, err := os.Stat(dir); err != nil {
			dir = "/sys/fs/cgroup"
		}
		if unix.Access(dir, unix.W_OK|unix.X_OK) == nil {
			return contract.SSHFeatureAvailable
		}
		return contract.SSHFeatureUnavailable
	}
	if _, err := sessionnet.DelegatedCgroupRoot("yuhaiin-ssh-probe"); err == nil {
		return contract.SSHFeatureAvailable
	}
	return contract.SSHFeatureUnavailable
}

func idMappings(m sessionnet.IDMap) []contract.SSHIDMapping {
	out := make([]contract.SSHIDMapping, 0, len(m))
	for _, r := range m {
		out = append(out, contract.SSHIDMapping{NamespaceID: r.NamespaceID, ParentID: r.ParentID, Count: r.Count})
	}
	return out
}

func idRanges(ranges []sessionnet.IDRange) []contract.SSHIDRange {
	out := make([]contract.SSHIDRange, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, contract.SSHIDRange{Start: r.Start, Count: r.Count})
	}
	return out
}
