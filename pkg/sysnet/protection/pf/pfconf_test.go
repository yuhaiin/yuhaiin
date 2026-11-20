package pf

import (
	"strings"
	"testing"
)

// The default /etc/pf.conf of macOS.
const macOSConf = `#
# Default PF configuration file.
#
# This file contains the main ruleset, which gets automatically loaded
# at startup.  PF will not be automatically enabled, however.  Instead,
# each component which utilizes PF is responsible for enabling and disabling
# PF via -E and -X as documented in pfctl(8).  That will ensure that PF
# is disabled only when the last enable reference is released.
#
# Care must be taken to ensure that the main ruleset does not get flushed,
# as the nested anchors rely on the anchor point defined here. In addition,
# to the anchors loaded by this file, some system services would dynamically
# insert anchors into the main ruleset. These anchors will be added only when
# the system service is used and would removed on termination of the service.
#
# See pf.conf(5) for syntax.
#

#
# com.apple anchor point
#
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
`

func TestRegisterDefaultMacOSConf(t *testing.T) {
	out, changed := Register(macOSConf, true)
	if !changed {
		t.Fatal("not changed")
	}
	want := strings.Replace(macOSConf, "rdr-anchor \"com.apple/*\"\n", "rdr-anchor \"com.apple/*\"\n"+natLine+"\n", 1)
	want = strings.Replace(want, "anchor \"com.apple/*\"\nload", filterLine+"\nanchor \"com.apple/*\"\nload", 1)
	if out != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
	// Idempotent.
	again, changed := Register(out, true)
	if changed || again != out {
		t.Fatal("registered twice")
	}
	reg := Registered(out)
	if !reg.Filter || !reg.NAT || !reg.Managed {
		t.Fatalf("registration = %+v", reg)
	}
	// Unregister restores the original byte for byte.
	back, changed := Unregister(out)
	if !changed || back != macOSConf {
		t.Fatalf("unregister:\n%q\nwant\n%q", back, macOSConf)
	}
}

func TestRegisterOrderIsValidForPF(t *testing.T) {
	out, _ := Register(macOSConf, true)
	var order []string
	for l := range strings.SplitSeq(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 && !strings.HasPrefix(f[0], "#") {
			order = append(order, f[0]+" "+strings.Trim(f[1], `"`))
		}
	}
	got := strings.Join(order, "\n")
	want := strings.Join([]string{"scrub-anchor com.apple/*", "nat-anchor com.apple/*", "rdr-anchor com.apple/*", "nat-anchor io.github.yuhaiin/*",
		"dummynet-anchor com.apple/*", "anchor io.github.yuhaiin/*", "anchor com.apple/*", "load anchor"}, "\n")
	if got != want {
		t.Fatalf("order:\n%s\nwant:\n%s", got, want)
	}
}

func TestRegisterCustomConfs(t *testing.T) {
	// Continuation lines, filter rules, and no translation rules.
	conf := "ext_if = \"en0\"\nset skip on lo0\npass out on $ext_if proto tcp \\\n  to any port 443\nblock in all\n"
	out, _ := Register(conf, true)
	want := "ext_if = \"en0\"\nset skip on lo0\n" + natLine + "\n" + filterLine + "\npass out on $ext_if proto tcp \\\n  to any port 443\nblock in all\n"
	if out != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
	// Empty file.
	out, _ = Register("", true)
	if out != natLine+"\n"+filterLine+"\n" {
		t.Fatalf("empty: %q", out)
	}
	// No trailing newline, filter only.
	out, _ = Register("anchor \"com.apple/*\"", false)
	if out != filterLine+"\nanchor \"com.apple/*\"\n" {
		t.Fatalf("no newline: %q", out)
	}
	// A comment containing the anchor name is not a registration.
	if Registered("# anchor \"io.github.yuhaiin/*\"\n").Filter {
		t.Fatal("comment counted")
	}
}

func TestUserRegistrationIsKept(t *testing.T) {
	// A line the user added by hand counts as registered and is never removed.
	conf := "anchor \"io.github.yuhaiin/*\"\nanchor \"com.apple/*\"\n"
	out, changed := Register(conf, false)
	if changed || out != conf {
		t.Fatalf("added a second anchor: %q", out)
	}
	if back, changed := Unregister(conf); changed || back != conf {
		t.Fatal("removed a user line")
	}
	reg := Registered(conf)
	if !reg.Filter || reg.Managed {
		t.Fatalf("registration = %+v", reg)
	}
}

func TestUnregisterKeepsOtherEdits(t *testing.T) {
	out, _ := Register(macOSConf, true)
	// Another program appends its own anchor afterwards.
	out += "anchor \"org.example.vpn\"\n"
	back, _ := Unregister(out)
	if back != macOSConf+"anchor \"org.example.vpn\"\n" {
		t.Fatalf("other edits lost:\n%s", back)
	}
	// Duplicated managed lines (an interrupted older edit) are all removed.
	dup := out + filterLine + "\n"
	back, _ = Unregister(dup)
	if strings.Contains(back, confMarker) {
		t.Fatal("duplicate managed line kept")
	}
}
