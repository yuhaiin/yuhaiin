// Package recovery owns deployment snapshots, authenticated restore planning,
// journaled activation, startup validation and rollback. It coordinates closed
// SQLite and file owners under the deployment lifecycle lock. The online backup
// scheduler consumes opaque prepared plans and never manipulates transactions.
package recovery
