package app

import (
	"context"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/prometheus/client_golang/prometheus"
)

var backupMetricTargets = [...]string{"local", "s3", "other"}
var backupMetricStates = [...]string{"queued", "capturing", "local_ready", "uploading", "verified", "failed", "deleting", "other"}

type backupMetricSnapshot struct {
	version      uint64
	states       [3][8]int
	lastComplete [2]float64
}

func (b *Backup) compileBackupMetrics(version uint64, items []contract.RecoveryBackup) {
	value := &backupMetricSnapshot{version: version}
	for _, item := range items {
		target, state := 2, 7
		for i, v := range backupMetricTargets {
			if v == item.Target {
				target = i
				break
			}
		}
		for i, v := range backupMetricStates {
			if v == item.State {
				state = i
				break
			}
		}
		value.states[target][state]++
		if target < 2 && (item.State == "verified" || (item.State == "local_ready" && item.Target == "local")) {
			value.lastComplete[target] = max(value.lastComplete[target], float64(item.CreatedAt.UnixMilli())/1000)
		}
	}
	for {
		old := b.metricsSnapshot.Load()
		if old != nil && old.version > version {
			return
		}
		if b.metricsSnapshot.CompareAndSwap(old, value) {
			return
		}
	}
}

func (b *Backup) refreshBackupMetrics(ctx context.Context) {
	if b.store == nil || ctx.Err() != nil {
		return
	}
	version := b.metricsVersion.Add(1)
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	items, err := b.store.RecoveryHistory(bounded)
	if err == nil {
		b.compileBackupMetrics(version, items)
	}
}

type backupCollector struct {
	backup                        *Backup
	jobs, lastComplete, downloads *prometheus.Desc
}

func (b *Backup) Metrics() prometheus.Collector {
	return &backupCollector{backup: b,
		jobs:         prometheus.NewDesc("yuhaiin_backup_recent_jobs", "Counts among the latest 1000 retained full-backup records; not cumulative counters.", []string{"target", "state"}, nil),
		lastComplete: prometheus.NewDesc("yuhaiin_backup_last_complete_timestamp_seconds", "Latest retained completed local ciphertext or verified S3 readback, not a successful restore drill.", []string{"target"}, nil),
		downloads:    prometheus.NewDesc("yuhaiin_backup_active_downloads", "Managed archive download leases protecting files from retention.", nil, nil),
	}
}
func (c *backupCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.jobs
	ch <- c.lastComplete
	ch <- c.downloads
}
func (c *backupCollector) Collect(ch chan<- prometheus.Metric) {
	// Scrapes read only immutable/atomic state, never SQLite, files or a provider.
	value := c.backup.metricsSnapshot.Load()
	for target, name := range backupMetricTargets {
		for state, label := range backupMetricStates {
			count := 0
			if value != nil {
				count = value.states[target][state]
			}
			ch <- prometheus.MustNewConstMetric(c.jobs, prometheus.GaugeValue, float64(count), name, label)
		}
		if target < 2 {
			timestamp := float64(0)
			if value != nil {
				timestamp = value.lastComplete[target]
			}
			ch <- prometheus.MustNewConstMetric(c.lastComplete, prometheus.GaugeValue, timestamp, name)
		}
	}
	ch <- prometheus.MustNewConstMetric(c.downloads, prometheus.GaugeValue, float64(c.backup.activeRecoveryDownloads.Load()))
}
