package backup

import (
	json "encoding/json/v2"
	"testing"
)

func TestRestoreOptionRestoreSourceUnmarshalLegacyString(t *testing.T) {
	var got RestoreOption
	if err := json.Unmarshal([]byte(`{"source":"s3"}`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.Source != RestoreOption_s3 {
		t.Fatalf("Source = %v, want %v", got.Source, RestoreOption_s3)
	}
}
