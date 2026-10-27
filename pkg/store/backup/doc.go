// Package backup persists backup settings, job history, import records and
// observed startup inputs through the existing SQLite handle. The archive child
// package owns encryption, streaming format and authenticated inventory checks.
// Constructing a Store creates no additional database owner or background work.
package backup
