// Package backup owns configuration backups and deployment recovery lifecycles.
// Its runtime accepts a backup store, outbound proxy and optional installed-host
// maintenance interface. It does not depend on the parent application package.
// Offline operations coordinate closed SQLite owners through the shared lifecycle
// lock; runtime transfers and scheduling share one bounded operation owner.
package backup
