package yuhaiin

import "testing"

func TestImportConfigRespectsRuntimeLock(t *testing.T) {
	SetSavePath(t.TempDir())
	GetStore().PutString("test-backup", "saved")
	data, err := ExportConfig()
	if err != nil {
		t.Fatal(err)
	}
	GetStore().PutString("test-backup", "changed")
	lock, err := lockConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if err := ImportConfig(data); err == nil {
		t.Fatal("restored while runtime lock was held")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ImportConfig(data); err != nil {
		t.Fatal(err)
	}
	if got := GetStore().GetString("test-backup"); got != "saved" {
		t.Fatalf("open preference handle did not see restore: %q", got)
	}
}
