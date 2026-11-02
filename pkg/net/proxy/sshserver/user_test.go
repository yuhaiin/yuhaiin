package sshserver

import "testing"

func TestPasswdLoginShell(t *testing.T) {
	passwd := "alice:x:1000:1000::/home/alice:/bin/bash\nservice:x:1001:1001::/:/usr/bin/nologin\n"
	for _, tc := range []struct{ uid, want string }{
		{"1000", "/bin/bash"}, {"1001", "/bin/sh"}, {"9999", "/bin/sh"},
	} {
		if got := passwdLoginShell(passwd, tc.uid); got != tc.want {
			t.Errorf("UID %s: got %q, want %q", tc.uid, got, tc.want)
		}
	}
	if got := passwdLoginShell("bad:entry\nalice:x:1000:1000::/home/alice:bash", "1000"); got != "/bin/sh" {
		t.Errorf("malformed passwd accepted: %q", got)
	}
}
