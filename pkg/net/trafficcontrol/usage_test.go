package trafficcontrol

import (
	"context"
	"testing"
)

func TestShapingUsageCounters(t *testing.T) {
	manager := NewManager()
	if err := manager.Apply(Config{Enabled: true, Global: Profile{
		Upload: Rate{BytesPerSecond: 1, BurstBytes: 1},
	}}); err != nil {
		t.Fatal(err)
	}
	policy := manager.Resolve("", "")
	if !policy.AllowDatagram(Upload, 1) {
		t.Fatal("initial datagram not admitted")
	}
	if policy.AllowDatagram(Upload, 1) {
		t.Fatal("rate limit not enforced")
	}
	if err := policy.WaitBytes(context.Background(), Download, 12); err != nil {
		t.Fatal(err)
	}
	got := manager.Usage()
	if got.AdmittedUploadBytes != 1 || got.RejectedUploadDatagrams != 1 || got.AdmittedDownloadBytes != 12 {
		t.Fatalf("invalid shaping usage: %+v", got)
	}
}
