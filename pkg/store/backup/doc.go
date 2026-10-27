// Package backup owns backup settings, recovery metadata and the authenticated
// streaming archive format. It uses the existing SQLite schemas and database
// handles; constructing a Store does not create another database owner or worker.
package backup
