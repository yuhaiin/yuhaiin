package app

import (
	"net/http"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/prometheus/client_golang/prometheus"
)

func TestBackupMetricsUseFiniteLabelsAndNoStoreOnScrape(t *testing.T) {
	b, _ := streamingBackup(t, func(http.ResponseWriter, *http.Request) { t.Error("metrics initiated network IO") })
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	items := []contract.RecoveryBackup{{ID: "private-id", Target: "s3", State: "verified", CreatedAt: time.Unix(100, 0)}}
	for range 1000 {
		items = append(items, contract.RecoveryBackup{Target: "https://unbounded.invalid/private", State: "arbitrary-user-text"})
	}
	version := b.metricsVersion.Add(1)
	b.compileBackupMetrics(version, items)
	// Remove the store entirely: collection must use only the compiled snapshot.
	b.store = nil
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(b.Metrics()); err != nil {
		t.Fatal(err)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, family := range families {
		count += len(family.Metric)
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetValue() == "https://unbounded.invalid/private" || label.GetValue() == "arbitrary-user-text" || label.GetValue() == "private-id" {
					t.Fatal("unbounded or private metric label")
				}
			}
		}
	}
	if count != 27 {
		t.Fatal("unexpected finite metric count", count)
	}
	// An old API request cannot replace a newer compiled observation.
	b.compileBackupMetrics(version-1, nil)
	if got := b.metricsSnapshot.Load().lastComplete[1]; got != 100 {
		t.Fatal("stale metrics overwrote a newer snapshot", got)
	}
}
