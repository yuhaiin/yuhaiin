package archive

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These checks run on a real Windows filesystem, with an intentionally
// permissive parent, to exercise inherited ACLs rather than Go mode bits.
func TestWindowsRecoveryArtifactsHavePrivateACLs(t *testing.T) {
	parent := t.TempDir()
	public, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := public.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	actualParent, err := windows.GetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	parentACL, _, err := actualParent.DACL()
	if err != nil || parentACL == nil || parentACL.AceCount != 1 {
		t.Fatalf("test parent did not retain its permissive ACL: %v", err)
	}
	var parentACE *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(parentACL, 0, &parentACE); err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil || parentACE.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !(*windows.SID)(unsafe.Pointer(&parentACE.SidStart)).Equals(everyone) {
		t.Fatal("test parent does not grant access to Everyone", err)
	}

	directory, manifest, identity := recoveryFixture(t)
	var encrypted bytes.Buffer
	if _, err := Write(t.Context(), &encrypted, directory, manifest, Encryption{Recipient: identity.Recipient().String()}); err != nil {
		t.Fatal(err)
	}
	prepared, err := Prepare(t.Context(), bytes.NewReader(encrypted.Bytes()), parent, Decryption{Identity: identity.String()})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	assertWindowsPrivateACL(t, prepared.Directory(), true)
	assertWindowsPrivateACL(t, filepath.Join(prepared.Directory(), "state.db"), false)
	assertWindowsPrivateACL(t, filepath.Join(prepared.Directory(), "identity", "device.json"), false)

	identityPath := filepath.Join(parent, "backup.key")
	if _, err := GenerateIdentityFile(t.Context(), identityPath); err != nil {
		t.Fatal(err)
	}
	assertWindowsPrivateACL(t, identityPath, true)
	archivePath := filepath.Join(parent, "backup.yhb")
	if _, err := WriteFile(t.Context(), archivePath, directory, manifest, Encryption{Recipient: identity.Recipient().String()}); err != nil {
		t.Fatal(err)
	}
	assertWindowsPrivateACL(t, archivePath, true)
}

func assertWindowsPrivateACL(t *testing.T, path string, protected bool) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil || protected && control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("unprotected DACL on %s: %v", path, err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		t.Fatalf("missing DACL on %s: %v", path, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	for i := range uint32(acl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("unexpected ACE on %s", path)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(user.User.Sid) && !sid.Equals(system) {
			t.Fatalf("unexpected principal %s can access %s", sid, path)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
