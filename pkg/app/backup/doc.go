// Package backup owns backup scheduling, transfer leases, managed jobs and
// expiring Web imports. Offline snapshot, activation and startup checks belong
// to recovery; archive owns the authenticated streaming format. The scheduler
// accepts its existing SQLite store, governed proxy and host maintenance adapter.
package backup
