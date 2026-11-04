These synthetic databases were created by the application at commit
`044c1b1f`, before migrating to purego-sqlite:

- `modernc-*`: default `modernc.org/sqlite v1.61.1`, `CGO_ENABLED=0`.
- `mattn-*`: `github.com/mattn/go-sqlite3 v1.14.52`, `CGO_ENABLED=1`,
  `-tags=sqlite_mattn,fts5`.

Each database was opened using `sqlite.Open` (configuration) or
`sqlite.OpenManagement` (management), allowing all existing migrations to run.
Three metadata rows were then inserted through SQL parameters:
`fixture_text = "历史配置\x00SQLite🌍"`, `fixture_blob = []byte{0,255,128,7}`,
and `fixture_empty_blob = []byte{}`. The store was closed before gzip compression.
They contain no user data or credentials.

`TestLegacyDriverDatabases` opens all four fixtures with the new backend,
checks integrity and values, inspects live WAL catalog state, writes new data,
vacuums a backup, verifies read-only snapshot enforcement and reopens the store.
Do not regenerate these fixtures using the new driver: their purpose is to
exercise the format and schema written by the previous application.
