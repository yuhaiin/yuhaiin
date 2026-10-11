package dataplane

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DNS application for a client tunnel, and the reason it lives beside the
// routes rather than in the caller.
//
// A full-tunnel VPN that routes every packet through the tunnel and still
// resolves names through the host's pre-VPN resolver leaks the entire query
// stream, in plaintext, from the host's real address -- while the user believes
// otherwise. That is the failure this file exists to close, and it is closed
// here because DNS state and route state have identical lifetimes and identical
// failure modes: both are installed by Apply, both must come back on Revert,
// and splitting them across two components is what let the gap open.
//
// Two backends, chosen by what the host runs:
//
//	systemd-resolved   resolvectl dns/domain on the tunnel link
//	anything else      rewrite /etc/resolv.conf, restoring the original
//
// The split is not cosmetic. On a host running resolved, writing
// /etc/resolv.conf accomplishes nothing at all: the file is a stub pointing at
// 127.0.0.53, and resolved keeps answering from whichever link it already knows
// about. Only a per-link setting moves the queries.

// newDNSBackend picks the mechanism that will actually take effect on this
// host. resolved is preferred whenever it is running AND resolvectl is on
// PATH -- without the tool there is nothing to drive it with, and falling
// through to resolv.conf at least leaves a trace an operator can see.
func newDNSBackend() dnsBackend {
	if _, err := os.Stat("/run/systemd/resolve"); err == nil {
		if path, err := exec.LookPath("resolvectl"); err == nil {
			return &resolvectlDNS{bin: path, run: run}
		}
	}
	return &resolvConfDNS{path: "/etc/resolv.conf"}
}

// resolvectlDNS drives systemd-resolved's per-link settings.
type resolvectlDNS struct {
	bin     string
	run     execRunner
	tun     string
	applied bool
}

func (d *resolvectlDNS) name() string { return "systemd-resolved" }

func (d *resolvectlDNS) apply(tun string, servers []net.IP, fullTunnel bool) error {
	args := []string{d.bin, "dns", tun}
	for _, s := range servers {
		args = append(args, s.String())
	}
	if err := d.run(args); err != nil {
		return err
	}
	// Claim the link as the resolver of last resort. "~." is resolved's routing
	// domain for "everything": without it the servers just set are consulted
	// only for names that some other rule already routes here, which for a
	// tunnel that has no search domain is no names at all.
	//
	// A split tunnel deliberately does not claim it. The user asked for some
	// prefixes to go through the VPN, not for their whole name space to.
	if fullTunnel {
		if err := d.run([]string{d.bin, "domain", tun, "~."}); err != nil {
			return err
		}
	}
	d.tun, d.applied = tun, true
	return nil
}

func (d *resolvectlDNS) revert() error {
	if !d.applied {
		return nil
	}
	d.applied = false
	// `revert` drops every per-link setting in one call, which is exactly the
	// scope we took: the link is ours and is about to disappear.
	return d.run([]string{d.bin, "revert", d.tun})
}

// resolvConfDNS rewrites /etc/resolv.conf, keeping the original bytes to put
// back. It also leaves a copy on disk, so that a veepin killed with SIGKILL --
// which runs no defer -- leaves the operator something to restore by hand
// rather than a file they have to reconstruct from memory.
type resolvConfDNS struct {
	path     string
	original []byte
	mode     os.FileMode
	applied  bool
}

func (d *resolvConfDNS) name() string { return "resolv.conf" }

// backupPath is where the pre-VPN file is parked. It is deliberately beside the
// original rather than in /tmp: the rename that installs our version must stay
// within one filesystem to be atomic, and an operator looking for the backup
// looks next to the file.
func (d *resolvConfDNS) backupPath() string { return d.path + ".veepin.bak" }

func (d *resolvConfDNS) apply(tun string, servers []net.IP, fullTunnel bool) error {
	// Refuse to clobber a file some other daemon owns. A symlink into /run is
	// how resolvconf(8), NetworkManager and resolved all publish a generated
	// file; overwriting the target corrupts their state, and overwriting the
	// link replaces a mechanism the host is relying on. Neither is ours to do.
	if fi, err := os.Lstat(d.path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		dest, err := os.Readlink(d.path)
		if err != nil {
			return fmt.Errorf("read %s symlink: %w", d.path, err)
		}
		if !filepath.IsAbs(dest) {
			dest = filepath.Join(filepath.Dir(d.path), dest)
		}
		if strings.HasPrefix(filepath.Clean(dest), "/run/") {
			return fmt.Errorf("%s is a symlink to %s, managed by another daemon; "+
				"configure DNS there or pass -no-dns", d.path, dest)
		}
	}

	orig, err := os.ReadFile(d.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", d.path, err)
	}
	mode := os.FileMode(0644)
	if fi, err := os.Stat(d.path); err == nil {
		mode = fi.Mode().Perm()
	}
	d.original, d.mode = orig, mode

	var b strings.Builder
	b.WriteString("# Generated by veepin for ")
	b.WriteString(tun)
	b.WriteString(". The previous file is at ")
	b.WriteString(d.backupPath())
	b.WriteString("\n")
	for _, s := range servers {
		b.WriteString("nameserver ")
		b.WriteString(s.String())
		b.WriteString("\n")
	}
	if !fullTunnel {
		// A split tunnel still needs the host's own resolvers for everything
		// outside the tunnel, and resolv.conf has no way to say which server
		// answers for which name -- so the tunnel's go first and the host's
		// follow. A full tunnel keeps only ours, because keeping any other is
		// the leak.
		b.WriteString(carryOverNameservers(orig))
	}

	if len(orig) > 0 {
		if err := os.WriteFile(d.backupPath(), orig, 0600); err != nil {
			return fmt.Errorf("back up %s: %w", d.path, err)
		}
	}
	if err := writeAtomic(d.path, []byte(b.String()), mode); err != nil {
		return err
	}
	d.applied = true
	return nil
}

func (d *resolvConfDNS) revert() error {
	if !d.applied {
		return nil
	}
	d.applied = false
	defer func() { _ = os.Remove(d.backupPath()) }()
	if len(d.original) == 0 {
		return os.Remove(d.path)
	}
	return writeAtomic(d.path, d.original, d.mode)
}

// carryOverNameservers returns the nameserver lines of the pre-VPN file, so a
// split tunnel keeps resolving the names that are not the VPN's business.
func carryOverNameservers(orig []byte) string {
	var b strings.Builder
	for line := range strings.SplitSeq(string(orig), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "nameserver ") {
			b.WriteString(strings.TrimSpace(line))
			b.WriteString("\n")
		}
	}
	return b.String()
}

// writeAtomic replaces path in one rename, so a reader never sees a half-written
// resolver list. The temp file is in the same directory because rename across
// filesystems is not a rename.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".veepin-resolv-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op once the rename has succeeded
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmp, path, err)
	}
	return nil
}
