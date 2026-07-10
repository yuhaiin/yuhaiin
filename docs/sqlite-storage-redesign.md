# SQLite Storage Redesign

## Background

Today the persistent state is split across JSON files and ad-hoc local stores:

- `config.json`
  - loaded through `pkg/chore/config.go`
  - most callers access it through `chore.DB.Batch/View`
- `node.json`
  - loaded through `pkg/node/manager.go`
  - `Manager` mutates a large in-memory protobuf tree and flushes the whole file on `Save()`
- Android keeps additional JSON-backed key/value stores in `cmd/android/store.go`
  - `yuhaiin_memory_store.json` stores app-level preferences and runtime-facing toggles
  - `yuhaiin_memory_config_store.json` stores protobuf payload bytes for Android config domains today
- Pebble is already used for caches and high-churn data such as connection statistics/history, fakeip disk cache, and temporary trie state

This works, but it keeps application state in large mutable protobuf objects even when the application only needs one small slice of data. A lot of business logic is currently expressed as:

1. load the whole config object
2. mutate nested maps/slices in memory
3. save the whole object back

That pattern is simple at first, but it creates several long-term costs:

- read paths depend on large in-memory snapshots instead of queryable storage
- write paths rewrite the full file even for tiny changes
- `node`, `resolver`, `inbound`, `rules`, and `lists` all pull data through a generic whole-config interface
- there is no transactional boundary across related row-level changes because there are no rows
- it is hard to answer questions like "list enabled inbounds", "load nodes in one group", "get due refresh jobs", or "find tag members" without first rebuilding the whole tree in memory

The goal of this redesign is not "store JSON inside SQLite". The goal is to make SQLite the source of truth for queryable application state, and let in-memory structures become runtime caches or runtime indexes only where they are actually needed.

## Goals

### Primary goals

- Replace JSON file persistence with SQLite on desktop/server and Android builds.
- Use relational tables for entities that are naturally queried by key, group, type, or schedule.
- Keep SQLite as the source of truth for persisted state.
- Reduce "load everything, mutate everything, save everything" code paths.
- Make writes transactional and migration-safe.
- Unify Android and non-Android persistent state around the same schema and storage layer.
- Keep Pebble only for data that is still better modeled as cache/stateful storage rather than relational data.

### Secondary goals

- Make startup hydration cheaper and more selective.
- Make future features like search, filtering, partial export, and audit/migration tools easier.
- Create a migration path that does not require a big-bang rewrite.

### Non-goals

- Replacing fakeip and trie temp caches in the first phase.
- Eliminating all runtime memory indexes. Some runtime structures should remain in memory for performance or side effects.
- Fully normalizing every protobuf field into individual SQL columns. Over-normalization would make the schema brittle and tedious to evolve.

## Design Principles

### 1. Query-driven normalization

Normalize entities that are regularly queried independently:

- nodes
- selected outbound nodes
- tags and tag members
- subscriptions
- publishes
- rules
- lists and refresh state
- resolvers
- dns hosts
- inbounds

Do not force singleton or opaque sections into dozens of tiny columns if the application almost always reads or writes them as a block. For those sections, use either:

- a dedicated singleton table, or
- a relational table with a `data_json TEXT` protojson payload plus a few indexed projection columns

### 2. SQLite is the source of truth

For persistent application state, the database wins. In-memory structures are:

- runtime indexes
- caches
- live listener/controller state
- derived search structures

If an in-memory map can be rebuilt from the database, it should not be treated as the canonical state.

### 3. Separate persistent state from runtime state

The database stores intent and persisted configuration. Runtime components still own:

- active inbound listeners
- active outbound dialers in `ProxyStore`
- loaded resolver instances
- fakeip live pool
- trie matching structures
- live connection handles and hot traffic counters

Write flow should generally become:

1. persist transactionally
2. commit
3. apply side effects to runtime components

### 4. Hybrid relational plus protojson payload

For many entities, the best tradeoff is:

- relational identity and query columns
- protobuf JSON payload stored as text for forward compatibility and low-friction evolution

Example:

- `nodes` table stores `hash`, `group_name`, `name`, `origin`, and `data_json TEXT`
- queries can filter/sort by relational columns
- the application can still reconstruct full protobuf messages from `protojson` without hand-mapping every nested protocol field into SQL columns

Use `protojson`, not protobuf binary:

- payloads stay inspectable in SQLite tooling
- debugging and migration validation become simpler
- JSON-based payloads fit better with the rest of the schema, which already uses SQL JSON checks in a few Android-specific places
- node search can be indexed from decoded JSON projections instead of trying to index opaque binary blobs

This keeps the database meaningfully relational without making schema maintenance painful.

### 5. Migration first, cleanup second

Phase 1 should establish the database and move data ownership there, even if compatibility adapters still exist. Code cleanup and API narrowing can follow once SQLite has become the stable source of truth.

## Proposed Storage Topology

### Database files

Replace `config.json` and `node.json` with a single database file:

- `state.db`

Android also uses the same `state.db` file as the source of truth instead of:

- `yuhaiin_memory_store.json`
- `yuhaiin_memory_config_store.json`

Keep existing non-relational stores as-is for now:

- `pebble_cache/`
- temporary trie databases
- logs
- lock file

Rationale for one database instead of `config.db` + `node.db`:

- simpler migration story
- easier transactional updates across settings and node state
- fewer open handles and fewer startup branches
- clearer ownership boundary: persisted app state lives in one place

## SQLite Configuration

Recommended defaults:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
PRAGMA temp_store = MEMORY;
```

Driver choice:

- use `modernc.org/sqlite`
- integrate through the standard `database/sql` package with driver name `sqlite`
- this keeps the implementation CGO-free while still using a mature SQLite binding across Linux, macOS, Windows, and Android

Rationale for choosing `modernc.org/sqlite`:

- it is a `database/sql` driver backed by a CGo-free port of SQLite
- the documented connection flow is the normal Go pattern:
  - import `_ "modernc.org/sqlite"`
  - open with `sql.Open("sqlite", dsn)`
- it already exposes SQLite-specific extension points if we need them later, such as connection hooks, custom scalar functions, collations, and virtual tables
- it avoids adding CGO constraints to build and release workflows

Dependency note:

- if the repo ends up importing `modernc.org/libc` directly for any reason, keep it aligned with the version required by the selected `modernc.org/sqlite` release
- if we only depend on `modernc.org/sqlite` through `go.mod`, normal module resolution should manage that for us

Recommended initialization shape:

```go
import (
    "database/sql"

    _ "modernc.org/sqlite"
)

func openStateDB(path string) (*sql.DB, error) {
    db, err := sql.Open("sqlite", path)
    if err != nil {
        return nil, err
    }

    pragmas := []string{
        "PRAGMA journal_mode = WAL;",
        "PRAGMA synchronous = NORMAL;",
        "PRAGMA foreign_keys = ON;",
        "PRAGMA busy_timeout = 5000;",
        "PRAGMA temp_store = MEMORY;",
    }

    for _, pragma := range pragmas {
        if _, err := db.Exec(pragma); err != nil {
            _ = db.Close()
            return nil, err
        }
    }

    return db, nil
}
```

Implementation note:

- the initial implementation should stay on plain `database/sql`
- only introduce driver-specific hooks from `modernc.org/sqlite` when there is a concrete need, for example connection initialization or custom SQL functions

## Package Layout

Suggested new packages:

```text
pkg/storage/
  store.go                 // root interfaces
  migrate.go               // migration runner and bootstrap logic
  legacy_import.go         // config.json/node.json import
  sqlite/
    open.go                // open db, pragmas, connection handling
    tx.go                  // transaction helpers
    schema/
      0001_init.sql
      0002_...
    repo/
      settings.go
      resolver.go
      inbound.go
      node.go
      route.go
      backup.go
```

Compatibility adapters during rollout:

- `pkg/chore/sqlite_db.go`
  - implements the current `chore.DB` interface on top of the new store
- `pkg/node/storage.go`
  - abstracts node persistence away from `jsondb.DB[*node.Node]`
- `cmd/android/store_sqlite.go`
  - replaces the current typed JSON-backed Android store with a SQLite-backed preference/config adapter during migration

## Logical Data Model

The schema should follow domain boundaries rather than protobuf file boundaries.

### 1. Metadata and schema versioning

```sql
CREATE TABLE metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE migrate (
    version     INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    applied_at  INTEGER NOT NULL
);
```

Examples:

- `schema_version`
- `legacy_import_done`
- `legacy_import_source`
- `created_at`

Design notes:

- `metadata` stores application/runtime markers
- `migrate` stores applied schema migrations only
- `metadata.schema_version` may still be kept as a convenience cache for diagnostics, but migration truth should come from `migrate`
- bootstrap should create both tables first, then run any pending migrations inside one transaction per migration step

### 1.5. Android app preferences and local app state

Android currently persists a second class of state outside the protobuf config tree:

- UI and app preferences like allow-LAN, sniff toggle, tun driver choice, battery profile, and network speed notification switch
- bootstrap/runtime values like the dynamically assigned local HTTP port
- protobuf byte payloads currently keyed by names like `inbound_db`, `resolver_db`, and similar

Those should also move into SQLite so Android no longer needs a sidecar JSON store.

Because these values are Android-app-specific and the key set may keep evolving, the design should use one small extension table rather than a fake typed KV table or a dedicated `android_preferences` singleton row.

```sql
CREATE TABLE android_extra_preferences (
    key         TEXT PRIMARY KEY,
    value_json  TEXT NOT NULL,
    updated_at  INTEGER NOT NULL,
    CHECK (json_valid(value_json))
);

CREATE INDEX android_extra_preferences_updated_at_idx
ON android_extra_preferences(updated_at);
```

Design notes:

- this table replaces the current typed maps in `cmd/android/store.go`
- `value_json` stores the real JSON scalar or JSON object, for example `true`, `1080`, `"balanced"`, or a small structured object if an Android-only preference later needs one
- this is intentionally not mixed into `settings_kv` or other cross-platform domain tables because these keys are not all part of the cross-platform config model
- this is not a place to keep long-term protobuf config blobs; `memoryConfigDB` should be migrated into the normal cross-platform domain tables
- there is intentionally no separate `android_preferences` singleton table in this design

### 2. General settings

These fields are small, singleton, and frequently read together.

```sql
CREATE TABLE settings_kv (
    section      TEXT NOT NULL,
    key          TEXT NOT NULL,
    value_json   TEXT NOT NULL CHECK (json_valid(value_json)),
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (section, key)
);

CREATE INDEX settings_kv_section_idx ON settings_kv(section);
```

Recommended keys:

- `('general', 'ipv6') -> false`
- `('general', 'use_default_interface') -> true`
- `('general', 'net_interface') -> "wlan0"`
- `('system_proxy', 'http') -> true`
- `('system_proxy', 'socks5') -> false`
- `('logcat', 'level') -> "info"`
- `('logcat', 'save') -> false`
- `('logcat', 'ignore_dns_error') -> false`
- `('advanced', 'udp_buffer_size') -> 2048`
- `('advanced', 'happyeyeballs_semaphore') -> 0`

Why use a key-value table here:

- these fields are stable
- they are read often
- they are still logically singleton settings, so four separate one-row tables would add schema noise without much benefit
- JSON scalar values let the storage stay simple without reintroducing type-split columns
- this still helps remove repeated whole-config rebuilds in `chore`

Boundary:

- `settings_kv` is only for top-level singleton scalar settings
- structured collections and independently queried entities still belong in their own domain tables

### 3. DNS domain

```sql
CREATE TABLE dns_settings (
    id                       INTEGER PRIMARY KEY CHECK (id = 1),
    server                   TEXT NOT NULL DEFAULT '',
    fakedns_enabled          INTEGER NOT NULL,
    fakedns_ipv4_range       TEXT NOT NULL DEFAULT '',
    fakedns_ipv6_range       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE dns_resolvers (
    name             TEXT PRIMARY KEY,
    resolver_type    INTEGER NOT NULL,
    host             TEXT NOT NULL,
    subnet           TEXT NOT NULL DEFAULT '',
    tls_servername   TEXT NOT NULL DEFAULT '',
    data_json        TEXT NOT NULL CHECK (json_valid(data_json))
);

CREATE TABLE dns_hosts (
    host    TEXT PRIMARY KEY,
    target  TEXT NOT NULL
);

CREATE TABLE dns_fakedns_lists (
    kind    TEXT NOT NULL,
    value   TEXT NOT NULL,
    PRIMARY KEY (kind, value)
);
```

Notes:

- `dns_resolvers.data_json` stores the full `config.Dns` payload encoded with `protojson`
- projected columns support direct query and filtering without re-decoding every row
- `kind` in `dns_fakedns_lists` is `whitelist` or `skip_check`

### 4. Inbound domain

```sql
CREATE TABLE inbound_settings (
    id                 INTEGER PRIMARY KEY CHECK (id = 1),
    hijack_dns         INTEGER NOT NULL,
    hijack_dns_fakeip  INTEGER NOT NULL,
    sniff_enabled      INTEGER NOT NULL
);

CREATE TABLE inbounds (
    name          TEXT PRIMARY KEY,
    enabled       INTEGER NOT NULL,
    inbound_type  TEXT NOT NULL,
    listen_host   TEXT NOT NULL DEFAULT '',
    updated_at    INTEGER NOT NULL,
    data_json     TEXT NOT NULL CHECK (json_valid(data_json))
);

CREATE INDEX inbounds_enabled_idx ON inbounds(enabled);
CREATE INDEX inbounds_type_idx ON inbounds(inbound_type);
```

`inbound_type` is derived from the selected oneof branch such as `http`, `socks5`, `mix`, `tun`, `yuubinsya`, and so on.

### 5. Node domain

This is the most important part of the redesign.

Node storage should include FTS in the first schema version, not as a later add-on. The canonical row stays in `nodes`, and search is powered by an explicit text projection instead of trying to index the full `data_json` document directly.

```sql
CREATE TABLE nodes (
    id           INTEGER PRIMARY KEY,
    hash         TEXT NOT NULL UNIQUE,
    group_name   TEXT NOT NULL,
    name         TEXT NOT NULL,
    origin       INTEGER NOT NULL,
    selected_tcp INTEGER NOT NULL DEFAULT 0 CHECK (selected_tcp IN (0, 1)),
    selected_udp INTEGER NOT NULL DEFAULT 0 CHECK (selected_udp IN (0, 1)),
    search_text  TEXT NOT NULL DEFAULT '',
    updated_at   INTEGER NOT NULL,
    data_json    TEXT NOT NULL CHECK (json_valid(data_json))
);

CREATE INDEX nodes_group_name_idx ON nodes(group_name, name);
CREATE INDEX nodes_origin_idx ON nodes(origin);
CREATE UNIQUE INDEX nodes_selected_tcp_one ON nodes(selected_tcp) WHERE selected_tcp = 1;
CREATE UNIQUE INDEX nodes_selected_udp_one ON nodes(selected_udp) WHERE selected_udp = 1;

CREATE VIRTUAL TABLE nodes_fts USING fts5(
    name,
    group_name,
    search_text,
    content='nodes',
    content_rowid='id'
);

CREATE TABLE node_tags (
    tag_name      TEXT NOT NULL,
    target_kind   TEXT NOT NULL CHECK (target_kind IN ('node', 'tag')),
    target_id     TEXT NOT NULL,
    updated_at    INTEGER NOT NULL,
    PRIMARY KEY (tag_name, target_kind, target_id),
    CHECK (tag_name <> target_id OR target_kind <> 'tag')
);

CREATE INDEX node_tags_target_idx ON node_tags(target_kind, target_id);

CREATE TABLE subscriptions (
    name          TEXT PRIMARY KEY,
    updated_at    INTEGER NOT NULL,
    data_json     TEXT NOT NULL CHECK (json_valid(data_json))
);

CREATE TABLE publishes (
    name          TEXT PRIMARY KEY,
    updated_at    INTEGER NOT NULL,
    data_json     TEXT NOT NULL CHECK (json_valid(data_json))
);
```

`search_text` is a denormalized search projection derived from the node payload. It should include the user-facing text that is actually useful to search, such as:

- node name
- group name
- protocol hostnames / server names / SNI-like fields
- transport remarks or aliases if present
- subscription or publish source names when they are part of the node identity

Do not point FTS directly at `data_json`:

- the canonical payload stays in `data_json`
- search quality is better when the indexed text is curated instead of dumping the whole serialized document
- the write path can deterministically rebuild `search_text` whenever a node changes

Selection state:

- `selected_tcp` and `selected_udp` live directly on `nodes`
- this matches the current code path more closely than a separate `selected_nodes` table
- partial unique indexes enforce that at most one node is selected for TCP and at most one node is selected for UDP
- the current `UsePoint` behavior sets both flags to the same row, but the schema still allows future divergence if the API ever grows that capability

Tag state:

- `node_tags` is a membership table, not a tag-header table plus a tag-member table
- each row means: tag `tag_name` contains one target `target_id`
- `target_kind='node'` means `target_id` is a node hash
- `target_kind='tag'` means `target_id` is another tag name, which covers the current `mirror` behavior
- `tag_type` is not stored; it is derived from membership shape instead
- a tag with only `node` members corresponds to the current `TagType_node`
- a tag with exactly one `tag` member and no `node` members corresponds to the current `TagType_mirror`
- mixed `node` + `tag` membership should be rejected by application logic in phase 1 to preserve current behavior
- there is intentionally no ordering column; tag membership is treated as a set

Synchronization strategy:

- `nodes` remains the content table
- `nodes_fts` is an external-content FTS5 table backed by `nodes.id`
- the application must keep `nodes_fts` synchronized with `nodes`
- the preferred initial implementation is application-managed sync inside the same write transaction
- if desired later, this may be switched to triggers, but triggers are not required for phase 1

Example query shape:

```sql
SELECT n.*
FROM nodes_fts f
JOIN nodes n ON n.id = f.rowid
WHERE nodes_fts MATCH ?
ORDER BY rank;
```

### 6. Rules and routing domain

```sql
CREATE TABLE route_settings (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    direct_resolver   TEXT NOT NULL DEFAULT '',
    proxy_resolver    TEXT NOT NULL DEFAULT '',
    resolve_locally   INTEGER NOT NULL,
    udp_proxy_fqdn    INTEGER NOT NULL
);

CREATE TABLE route_rules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,
    priority     INTEGER NOT NULL,
    disabled     INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    data_json    TEXT NOT NULL CHECK (json_valid(data_json))
);

CREATE UNIQUE INDEX route_rules_priority_idx ON route_rules(priority);
```

Why explicit `priority`:

- rule reordering becomes an SQL update instead of slice surgery in a large protobuf
- list and reorder queries become direct

### 7. Lists and refresh state

```sql
CREATE TABLE route_lists (
    name         TEXT PRIMARY KEY,
    kind         TEXT NOT NULL DEFAULT '',
    updated_at   INTEGER NOT NULL,
    data_json    TEXT NOT NULL CHECK (json_valid(data_json))
);

CREATE TABLE route_list_refresh (
    name               TEXT PRIMARY KEY,
    refresh_interval   INTEGER NOT NULL,
    last_refresh_time  INTEGER NOT NULL DEFAULT 0,
    last_error         TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (name) REFERENCES route_lists(name) ON DELETE CASCADE
);

CREATE INDEX route_list_refresh_due_idx
ON route_list_refresh(refresh_interval, last_refresh_time);
```

This removes the need to rebuild due-refresh logic from a whole settings object. The downloader can directly ask for due jobs.

### 8. Backup domain

```sql
CREATE TABLE backup_settings (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    updated_at  INTEGER NOT NULL,
    data_json   TEXT NOT NULL CHECK (json_valid(data_json))
);
```

Design notes:

- `backup_settings.data_json` stores `config.BackupOption` encoded with `protojson`
- the backup artifact itself is not stored in SQLite rows; it is a consistent snapshot of the `state.db` file
- full backup should default to copying/uploading a SQLite snapshot instead of re-materializing all domains into `backup.BackupContent` JSON
- restore should default to swapping in a SQLite snapshot and then reopening the database, which is substantially faster than replaying every domain write through the API layer
- if selective restore must remain supported, do it by attaching the backup database and copying only the selected domain tables inside transactions, not by reintroducing logical JSON replay as the primary path
- the old JSON export format may remain as a secondary debugging/import tool if needed later, but it is no longer the main backup format in this redesign

### 9. Statistics and connection telemetry

Several runtime-facing data sets currently live in `pkg/statistics` with a mix of memory, LRU state, and Pebble-backed blobs:

- total upload/download flow counters
- currently open connection metadata
- all-history aggregates
- failed-connection aggregates

These are good candidates for SQLite persistence as long as the write path remains buffered. The hot path should still update in-memory counters first and flush batched deltas to SQLite.

```sql
CREATE TABLE statistics_kv (
    key         TEXT PRIMARY KEY CHECK (key IN ('total_download', 'total_upload')),
    value_int   INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE traffic_hourly (
    bucket_start_utc  INTEGER PRIMARY KEY,
    upload_bytes      INTEGER NOT NULL DEFAULT 0,
    download_bytes    INTEGER NOT NULL DEFAULT 0,
    updated_at        INTEGER NOT NULL
);

CREATE TABLE connection_sessions (
    id             INTEGER PRIMARY KEY,
    opened_at      INTEGER NOT NULL,
    last_seen_at   INTEGER NOT NULL,
    closed_at      INTEGER,
    state          TEXT NOT NULL CHECK (state IN ('open', 'closed', 'interrupted')),
    protocol       INTEGER NOT NULL,
    process_name   TEXT NOT NULL DEFAULT '',
    inbound        TEXT NOT NULL DEFAULT '',
    inbound_name   TEXT NOT NULL DEFAULT '',
    outbound       TEXT NOT NULL DEFAULT '',
    network        TEXT NOT NULL DEFAULT '',
    destination    TEXT NOT NULL DEFAULT '',
    host           TEXT NOT NULL DEFAULT '',
    upload_bytes   INTEGER NOT NULL DEFAULT 0,
    download_bytes INTEGER NOT NULL DEFAULT 0,
    summary_json   TEXT NOT NULL CHECK (json_valid(summary_json))
);

CREATE INDEX connection_sessions_state_idx
ON connection_sessions(state, last_seen_at DESC);

CREATE INDEX connection_sessions_opened_at_idx
ON connection_sessions(opened_at DESC);

CREATE TABLE connection_history (
    protocol             INTEGER NOT NULL,
    addr                 TEXT NOT NULL,
    process_name         TEXT NOT NULL DEFAULT '',
    hit_count            INTEGER NOT NULL,
    last_seen_at         INTEGER NOT NULL,
    last_connection_json TEXT NOT NULL CHECK (json_valid(last_connection_json)),
    PRIMARY KEY (protocol, addr, process_name)
);

CREATE INDEX connection_history_last_seen_idx
ON connection_history(last_seen_at DESC);

CREATE TABLE failed_connection_history (
    protocol       INTEGER NOT NULL,
    host           TEXT NOT NULL,
    process_name   TEXT NOT NULL DEFAULT '',
    failed_count   INTEGER NOT NULL,
    last_seen_at   INTEGER NOT NULL,
    last_error     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (protocol, host, process_name)
);

CREATE INDEX failed_connection_history_last_seen_idx
ON failed_connection_history(last_seen_at DESC);
```

Design notes:

- `statistics_kv` is the right place for tiny scalar counters; this is one of the few domains where a small KV table is simpler than a dedicated singleton row
- `traffic_hourly` is the canonical time-series table for flow statistics; one row represents one UTC hour bucket
- daily / monthly / yearly traffic should be derived from `traffic_hourly` with SQL aggregation instead of maintaining four separate write paths
- the row count is naturally small enough for this approach: one year of hourly buckets is only about `24 * 365 = 8760` rows
- bucket boundaries should be stored in UTC; when the UI wants calendar-day or calendar-month results, the query should apply an explicit timezone offset before grouping
- `connection_sessions` holds metadata only for connections owned by the current process; final history is persisted in `connection_history` and `failed_connection_history`
- `summary_json` and `last_connection_json` store `statistic.Connection` encoded with `protojson`
- `connection_history` mirrors the current dedupe shape in `pkg/statistics/history.go`: `(protocol, addr, process_name)` with a hit count and latest connection snapshot
- `failed_connection_history` mirrors the current failed-history dedupe shape in `pkg/statistics/history.go`: `(protocol, host, process_name)` with last error and failed count
- on startup, clear all `connection_sessions` rows left by the previous process
- high-frequency byte increments should stay in memory briefly and flush to SQLite in batches; do not issue one SQL write per read/write syscall
- history retention should still respect `configuration.HistorySize` or an equivalent cap by pruning oldest rows after inserts
- route reject history can move later using the same pattern, but it does not need to block the first SQLite statistics migration

Example query shapes:

```sql
-- hourly
SELECT
    bucket_start_utc,
    download_bytes,
    upload_bytes
FROM traffic_hourly
WHERE bucket_start_utc >= :from_utc
  AND bucket_start_utc < :to_utc
ORDER BY bucket_start_utc;

-- daily, grouped in the caller's timezone offset
SELECT
    strftime('%Y-%m-%d', bucket_start_utc + :tz_offset_seconds, 'unixepoch') AS day_bucket,
    SUM(download_bytes) AS download_bytes,
    SUM(upload_bytes) AS upload_bytes
FROM traffic_hourly
WHERE bucket_start_utc >= :from_utc
  AND bucket_start_utc < :to_utc
GROUP BY day_bucket
ORDER BY day_bucket;

-- monthly / yearly use the same pattern with '%Y-%m' or '%Y'
```

## Domain Ownership and Runtime Consumers

| Domain | Persistent owner | Runtime consumer |
| --- | --- | --- |
| general settings | `SettingsStore` | `configuration`, `log.Controller`, sysproxy |
| dns resolvers and hosts | `ResolverStore` | `ResolverCtr`, `Hosts`, `Fakedns` |
| inbounds | `InboundStore` | `InboundCtr`, live listeners |
| nodes, tags, subscriptions, publishes | `NodeStore` | `node.Manager`, `ProxyStore` |
| route rules and route lists | `RouteStore` | `Rules`, `Lists`, `Route` |
| backup settings | `BackupStore` | `app.Backup` |
| statistics and connection telemetry | `TelemetryStore` | `statistics.Connections`, notify stream |
| Android app preferences | `AppPreferenceStore` | `cmd/android/yuhaiin.go`, runtime profile application |

The key rule is:

- persistent stores answer "what should exist"
- runtime components answer "what is currently running"

## Persistence Interfaces

The new storage layer should expose domain-specific interfaces instead of one generic whole-config object.

```go
type Store interface {
    Tx(ctx context.Context, fn func(Store) error) error

    AppPreference() AppPreferenceStore
    Settings() SettingsStore
    Resolver() ResolverStore
    Inbound() InboundStore
    Node() NodeStore
    Route() RouteStore
    Backup() BackupStore
    Telemetry() TelemetryStore
    Close() error
}
```

`Tx(...)` passes a transaction-bound `Store` view into the callback. In other words, callers use the same domain store interfaces inside and outside a transaction; the only difference is whether the implementation is bound to a live SQL transaction.

Example Android-facing preference API:

```go
type AppPreferenceStore interface {
    GetString(ctx context.Context, key string) (string, bool, error)
    PutString(ctx context.Context, key, value string) error
    GetInt(ctx context.Context, key string) (int32, bool, error)
    PutInt(ctx context.Context, key string, value int32) error
    GetBool(ctx context.Context, key string) (bool, bool, error)
    PutBool(ctx context.Context, key string, value bool) error
    GetLong(ctx context.Context, key string) (int64, bool, error)
    PutLong(ctx context.Context, key string, value int64) error
    GetFloat(ctx context.Context, key string) (float32, bool, error)
    PutFloat(ctx context.Context, key string, value float32) error
    GetBytes(ctx context.Context, key string) ([]byte, bool, error)
    PutBytes(ctx context.Context, key string, value []byte) error
    Delete(ctx context.Context, key string) error
}
```

This store exists for Android app-level state only and is backed by `android_extra_preferences`. Cross-platform config should still flow through the domain stores above.

Implementation note:

- if `GetBytes/PutBytes` survives for migration compatibility, encode bytes into `value_json` in a small tagged JSON shape instead of reintroducing parallel typed columns
- the new shared schema should not store protobuf payloads as raw binary columns; domain stores should serialize with `protojson`

Example domain-specific APIs:

```go
type NodeStore interface {
    SaveNodes(ctx context.Context, nodes ...*node.Point) error
    DeleteNode(ctx context.Context, hash string) error
    ListNodesByGroup(ctx context.Context) (map[string][]*node.Point, error)
    GetNode(ctx context.Context, hash string) (*node.Point, bool, error)

    SetSelectedNode(ctx context.Context, network string, hash string) error
    GetSelectedNode(ctx context.Context, network string) (*node.Point, bool, error)

    SaveTag(ctx context.Context, tag *node.Tags) error
    DeleteTag(ctx context.Context, name string) error
    ListTags(ctx context.Context) (map[string]*node.Tags, error)

    SaveLinks(ctx context.Context, links ...*node.Link) error
    DeleteLinks(ctx context.Context, names ...string) error
    ListLinks(ctx context.Context) (map[string]*node.Link, error)

    SavePublish(ctx context.Context, name string, p *node.Publish) error
    DeletePublish(ctx context.Context, name string) error
    ListPublishes(ctx context.Context) (map[string]*node.Publish, error)
}
```

This is intentionally narrower than `jsondb.DB`. The storage layer should expose operations that match business intent.

Example telemetry-facing API:

```go
type TelemetryStore interface {
    AddTotalDownload(ctx context.Context, n uint64) error
    AddTotalUpload(ctx context.Context, n uint64) error
    GetTotals(ctx context.Context) (download uint64, upload uint64, err error)
    AddTrafficSample(ctx context.Context, at time.Time, download uint64, upload uint64) error
    QueryTrafficSeries(ctx context.Context, granularity TrafficGranularity, from time.Time, to time.Time, tzOffsetSeconds int) ([]TrafficBucket, error)

    OpenConnection(ctx context.Context, conn *statistic.Connection) error
    UpdateConnectionCounters(ctx context.Context, id uint64, download uint64, upload uint64, lastSeenAt time.Time) error
    CloseConnection(ctx context.Context, id uint64, download uint64, upload uint64, closedAt time.Time) error
    ListOpenConnections(ctx context.Context) ([]*statistic.Connection, error)

    UpsertHistory(ctx context.Context, conn *statistic.Connection, seenAt time.Time) error
    ListHistory(ctx context.Context, limit int) ([]*api.AllHistory, error)

    UpsertFailedHistory(ctx context.Context, protocol statistic.Type, host string, process string, errText string, seenAt time.Time) error
    ListFailedHistory(ctx context.Context, limit int) ([]*api.FailedHistory, error)

    MarkInterruptedConnections(ctx context.Context, interruptedAt time.Time) error
    PruneHistory(ctx context.Context, limit int) error
}
```

## Read and Write Flows

### Node save

Current behavior:

- mutate `Manager.db.Data`
- save whole `node.json`

New behavior:

1. `NodeStore.SaveNodes(...)` writes rows to `nodes`
2. rebuilds `search_text` and updates `nodes_fts` in the same transaction
3. commit transaction
4. `ProxyStore.Refresh` is applied only for affected active nodes

### Use point

Current behavior:

- mutate `tcp` and `udp` embedded point copies in memory
- save whole `node.json`

New behavior:

1. fetch selected node row by hash
2. clear the old `selected_tcp` / `selected_udp` flags and set the new flags on the chosen node
3. commit transaction
4. clear/update runtime dialer cache as needed

### Resolver save

Current behavior:

- modify `s.GetDns().GetResolver()[name]`
- write whole settings object

New behavior:

1. upsert one row in `dns_resolvers`
2. commit
3. apply `Resolver.Apply(name, resolver)` side effect

### List refresh

Current behavior:

- load route config from whole settings object
- mutate refresh timestamps and error strings inside nested protobuf

New behavior:

1. query `route_list_refresh` for due rows
2. refresh each list
3. update only `last_refresh_time` and `last_error`
4. if the list payload changed, update `route_lists.data_json`

### Backup / restore

Current behavior:

- enumerate each domain through service APIs
- build a `backup.BackupContent` document
- upload/download JSON
- restore by replaying rows back through per-domain mutation paths

New behavior:

1. create a consistent snapshot of `state.db`
2. compute a content hash from the snapshot bytes
3. if unchanged, skip copy/upload when policy allows
4. copy the snapshot locally or upload it to remote storage as the backup artifact
5. on restore, stop writers and close the active SQLite handle
6. for full restore, atomically replace the current `state.db` with the snapshot
7. reopen SQLite, run pending migrations, and rehydrate runtime caches/controllers
8. for selective restore, attach the backup database and copy only the requested tables/rows in transactions

Snapshot creation notes:

- prefer the SQLite backup mechanism exposed by the driver if it is available in `modernc.org/sqlite`
- otherwise, create the artifact with a SQLite-native snapshot step such as `VACUUM INTO` to a temporary file
- avoid filesystem-level blind copies of a live database connection unless the connection has been quiesced first

### Statistics / connection telemetry

Current behavior:

- keep active connection objects in memory
- keep total counters in memory with periodic Pebble sync
- keep history and failed-history in LRU structures, with some connection payloads written into Pebble buckets

New behavior:

1. create/open connection rows in `connection_sessions` when connections are observed
2. keep the actual closable connection handles and per-connection hot counters in memory
3. flush aggregated byte deltas to `statistics_kv` and `traffic_hourly` on a timer, threshold, or close; remove the session row when its connection closes
4. upsert deduplicated rows into `connection_history` and `failed_connection_history`
5. on restart, clear leftover session rows before accepting new connections

This means SQLite becomes the persisted source of truth for telemetry, while memory still owns the live objects and the sub-second write buffer.

Traffic aggregation rule:

- every flushed traffic delta is assigned to the UTC hour bucket that contains its flush timestamp
- daily / monthly / yearly traffic are query-time rollups over `traffic_hourly`
- if later profiling shows these rollups become expensive, materialized daily buckets can be added as an optimization, but they are not required in the first design

## Runtime Caching Strategy

Moving to SQLite should simplify state ownership, but not every read should hit the database blindly.

Recommended runtime model:

- `ProxyStore`
  - keep as runtime cache of active dialers
  - source of truth for node definitions is SQLite
- `Resolver`
  - runtime map of instantiated resolvers remains in memory
  - SQLite stores configuration and names
- `Hosts`, `Fakedns`, `Lists`
  - runtime search structures remain in memory
  - they are hydrated from SQLite on startup and on writes
- `statistics.Connections`
  - live `net.Conn` / `net.PacketConn` handles and notify subscribers remain in memory
  - persisted totals/history/session metadata move to SQLite with buffered flushes
- fakeip state
  - persisted in SQLite (`fakeip_entries` and cursor metadata)
  - legacy Pebble buckets are imported once during application startup before
    the FakeDNS runtime pool opens; both the prefix-named buckets and the old
    `fakedns_cache` / `fakedns_cachev6` layouts are supported
- trie temp state
  - remains on Pebble

This gives a clean split:

- SQLite for persisted intent
- memory for live objects and derived indexes

## Compatibility Adapters

To avoid a disruptive big-bang refactor, keep temporary adapters.

### `chore.DB` adapter

Implement the existing interface on top of SQLite:

- `View(...)`
  - reconstruct a `config.Setting` protobuf from the database
- `Batch(...)`
  - reconstruct `config.Setting`
  - run mutation callbacks
  - diff or rewrite affected domains back into tables

This adapter is not the final target, but it allows:

- immediate migration away from JSON
- incremental refactors of `resolver`, `route`, `inbound`, and `backup`

### Node adapter

Introduce a persistence abstraction for `node.Manager` before deeply rewriting manager logic.

Initial interface:

```go
type NodeState interface {
    Load(ctx context.Context) (*node.Node, error)
    Save(ctx context.Context, n *node.Node) error
}
```

Then tighten it later into `NodeStore` operations once the manager is ready to stop thinking in terms of one giant `node.Node` document.

This gives a safer bridge:

1. SQLite replaces JSON as storage
2. manager internals are gradually taught to query rows directly

## Migration Plan

### Bootstrap order

On startup:

1. open `state.db`
2. run schema migrations
3. if database is empty and legacy files exist:
   - import `config.json`
   - import `node.json`
   - on Android, also import `yuhaiin_memory_store.json`
   - on Android, also import `yuhaiin_memory_config_store.json`
4. mark import success in `metadata`
5. rename legacy files to backup names

Suggested backup names:

- `config.json.migrated.bak`
- `node.json.migrated.bak`
- `yuhaiin_memory_store.json.migrated.bak`
- `yuhaiin_memory_config_store.json.migrated.bak`

### Import semantics

Import should be one transaction:

1. parse legacy JSON into protobufs using the current defaults/merge behavior
2. on Android, parse typed key/value state from `yuhaiin_memory_store.json`
3. on Android, parse config payload bytes from `yuhaiin_memory_config_store.json`
4. write all normalized tables
5. write Android app preferences into `android_extra_preferences`
6. if Android legacy config payloads exist, decode them and write them back as `protojson` text into the same normalized config tables
7. write metadata markers
8. commit

If import fails:

- rollback transaction
- keep legacy files untouched
- do not leave a half-populated database

### Idempotence

Import must be safe to retry if the process crashes before the success marker and backup rename complete.

Rule:

- `metadata.legacy_import_done = true` means import will never run again unless manually reset

### Android migration notes

Android should not keep a parallel long-term config path once SQLite lands.

Migration target:

- `memoryDB` data becomes rows in `android_extra_preferences`
- `memoryConfigDB` data becomes normal rows in the same `state.db` schema used by desktop/server

Recommended order on Android:

1. migrate `memoryDB` and `memoryConfigDB` into `state.db`
2. switch Android startup to read runtime toggles from `AppPreferenceStore`
3. switch Android config adapters to use the same config stores as other platforms
4. delete the old JSON-backed `memoryStore` implementation

## Migration of Existing Code

### Phase 1: introduce storage and import

- add `pkg/storage`
- add `state.db` bootstrap
- add JSON-to-SQLite import for `config.json`, `node.json`, and Android legacy store files
- keep current service APIs unchanged

### Phase 2: move `chore.DB` to SQLite-backed adapter

- switch CLI/macOS startup from `NewJsonDB(...)` to `NewSqliteDB(...)`
- switch Android config DB constructors to SQLite-backed storage under the existing `configDB` compatibility layer
- keep `route`, `resolver`, `inbound`, `backup` callers unchanged initially

### Phase 3: refactor node persistence

- replace `jsondb.DB[*node.Node]` in `pkg/node/manager.go`
- move `nodes`, `tags`, `links`, `publishes`, and selected node state into stores
- stop treating one giant `node.Node` protobuf as the canonical in-memory store

### Phase 4: replace whole-config mutation paths with repo-specific writes

Refactor these areas to stop depending on generic `Batch/View`:

- `pkg/resolver/resolver.go`
- `pkg/route/rule.go`
- `pkg/route/list.go`
- `pkg/inbound/store.go`
- `pkg/app/backup.go` for snapshot-based backup/restore instead of logical JSON assembly
- `cmd/android/store.go`
- `cmd/android/yuhaiin.go`

### Phase 5: complete Android store migration

- replace `GetStore()` JSON-backed persistence with `AppPreferenceStore`
- remove `memoryDB` and `memoryConfigDB`
- stop storing protobuf config payloads in Android-specific byte blobs and persist them as `protojson` text in the shared tables
- share the same schema, migrations, and import code paths across all supported platforms

### Phase 6: migrate statistics persistence to SQLite

- [x] replace Pebble-backed `flow_data`, `connection_data`, and `history_data` paths in `pkg/statistics`
- keep live connection handles and notify machinery in memory
- flush total counters and per-connection byte deltas to SQLite in batches
- add hourly traffic buckets and expose daily/monthly/yearly aggregation queries on top
- move all-history and failed-history queries to `TelemetryStore`
- clear session rows during startup bootstrap; history remains in the dedicated history tables

Compatibility import:

- during application startup, before the statistics and FakeDNS runtime objects
  are created, import the legacy Pebble `flow_data` totals and FakeIP buckets
  into SQLite
- imports use persistent metadata markers and fail startup on an import error;
  runtime constructors do not accept a legacy cache and cannot run a hidden
  migration

## Implementation Order Checklist

Use this as the execution order for the actual migration work:

- [x] Bootstrap SQLite skeleton
  Completion:
  `pkg/storage` exists, `state.db` opens successfully, `metadata` / `migrate` tables are created, and migrations can run on an empty database.
- [x] Land the initial schema
  Completion:
  core config tables, `nodes_fts`, backup tables, Android preference tables, and telemetry tables all exist in the first migration series.
- [x] Import legacy JSON and Android legacy stores
  Completion:
  `config.json`, `node.json`, `yuhaiin_memory_store.json`, and `yuhaiin_memory_config_store.json` can be imported transactionally and idempotently.
- [x] Switch app startup to SQLite-backed `chore.DB`
  Completion:
  desktop/server and Android startup paths open SQLite first, and existing callers still work through the compatibility layer.
- [x] Move Android app preferences to `AppPreferenceStore`
  Completion:
  runtime toggles and Android-only preferences are read/written from `android_extra_preferences`, with old JSON-backed stores no longer on the read path.
- [x] Replace node JSON persistence
  Completion:
  `pkg/node/manager.go` no longer treats `node.json` as the source of truth, and node/tag/link/publish state persists in SQLite.
- [ ] Refactor resolver / route / inbound / backup writes onto domain stores
  Completion:
  resolver / route / inbound stop depending on whole-document mutation for normal writes. Backup already uses SQLite snapshot semantics.
- [x] Remove Android legacy config blobs
  Completion:
  `memoryConfigDB` / `configDB` compatibility code is deleted. `memoryDB` remains only as the import source for old Android app preferences.
- [x] Migrate telemetry persistence
  Completion:
  totals, sessions, history, failed history, and hourly traffic buckets persist in SQLite; open connection handles remain runtime-only.
- [x] Add traffic rollup APIs
  Completion:
  callers can query hourly, daily, monthly, and yearly traffic series from `traffic_hourly` through the SQLite telemetry backend.
- [ ] Prune old persistence code
  Completion:
  obsolete JSON storage paths, import-only shims, and Pebble-backed telemetry persistence code are removed once replacement coverage is verified.

Suggested verification gates between checklist items:

- [x] Empty-db bootstrap test passes
- [x] Legacy import test passes
- [x] Restart idempotence test passes
- [x] Node FTS search test passes
- [x] Android preference read/write test passes
- [x] Snapshot backup/restore test passes
- [ ] Telemetry interrupted-session test passes
- [ ] Hourly-to-daily/monthly/yearly traffic aggregation test passes

## Why This Simplifies the Codebase

The main simplification is not "fewer lines of code in a storage package". The simplification is that services stop pretending the whole application state is one mutable document.

Examples:

- listing nodes by group becomes one indexed query
- full-text node search is available immediately through `nodes_fts`
- resolver CRUD stops rebuilding the full settings protobuf
- inbound startup can query only enabled listeners
- route refresh scheduler can query only due lists
- rule ordering becomes an explicit persisted priority instead of slice surgery
- selected outbound state becomes first-class data instead of embedded copies inside a large tree
- traffic/history/failed-connection views stop depending on Pebble-specific buckets and ad-hoc in-memory mirrors

This should reduce:

- broad lock scopes around giant in-memory objects
- accidental overwrites between unrelated settings domains
- future schema pain when features need filtering or partial updates

## Performance Considerations

Expected wins:

- no full-file rewrite for small updates
- selective startup hydration
- indexed reads for common administrative queries
- simpler incremental updates

Expected costs:

- row decoding and transaction overhead
- SQLite single-writer contention if write frequency becomes very high
- more storage code than a trivial JSON helper

Mitigation:

- use WAL
- keep only the truly hot sub-second deltas in memory and batch SQLite writes
- batch related writes in one transaction
- avoid chatty write patterns for runtime counters

## Testing Strategy

### Unit tests

- schema migration tests
- legacy import tests from sample `config.json` and `node.json`
- repo CRUD tests per domain
- transaction rollback tests
- adapter compatibility tests for `chore.DB`
- statistics delta-flush and interrupted-session tests
- hourly-to-daily/monthly/yearly traffic aggregation tests

### Integration tests

- start app with empty `state.db`
- start app with legacy JSON only and verify import
- on Android, start with legacy memory-store JSON files and verify import
- restart after import and verify idempotence
- save node/resolver/inbound/rule/list through public APIs and verify persisted rows
- save/update/delete nodes and verify `nodes_fts` stays in sync
- verify `MATCH` queries return the expected nodes for name/group/host search terms
- verify Android app preference reads and writes through SQLite
- create a SQLite snapshot backup, restore from it, and verify the restored app boots without logical re-import
- verify selective restore copies only the requested domains from an attached backup database
- restart with open connections recorded in SQLite and verify they become `interrupted`
- verify history pruning keeps only the newest configured rows
- verify hourly traffic buckets aggregate correctly across day / month / year boundaries

### Regression tests

- preserve current default-merge semantics
- preserve selected tcp/udp marker behavior and uniqueness guarantees
- preserve node-tag resolution semantics without persisting a separate `tag_type`
- preserve backup scheduling semantics while switching the artifact format to SQLite snapshots
- preserve total flow counters and history semantics while changing the persistence backend
- preserve traffic rollup correctness for hourly, daily, monthly, and yearly queries

When running Go tests in this repo, continue using `GOEXPERIMENT=jsonv2,greenteagc`.

## Risks and Open Questions

### 1. How far to normalize protobuf-heavy entities

Recommendation:

- normalize identity and query columns
- keep full protobuf payload in `data_json TEXT` encoded by `protojson`
- only split additional columns when there is a concrete query need

### 2. Whether to keep the temporary `chore.DB` adapter for long

Recommendation:

- use it to de-risk migration
- do not let it become permanent

The long-term target is domain stores, not whole-config callbacks.

### 3. Android migration complexity

Recommendation:

- Android is part of the migration target, not a future follow-up
- keep Android-only app preferences isolated in `android_extra_preferences`
- avoid preserving the old Android `bytes`-backed config pattern after the migration bridge is no longer needed

### 4. Listener side effects inside transactions

Recommendation:

- do not start/stop listeners before commit
- persist first, then apply runtime side effects

## Recommended First Implementation Slice

The best first slice is:

1. add `state.db` and schema
2. include `nodes_fts` and node search projection logic in the initial schema
3. import legacy JSON and Android legacy store files
4. move `chore.DB` to SQLite-backed storage
5. add `AppPreferenceStore` and switch Android runtime toggles to SQLite
6. keep node persistence temporarily document-shaped but stored in SQLite
7. then refactor node/rules/resolver/inbound/lists one domain at a time toward true row-level stores
8. migrate statistics/history persistence after the core config domains are stable

This sequence gives fast value:

- JSON files are gone early
- Android no longer has a parallel persistence model
- migration risk stays manageable
- the codebase gets a clear target architecture
- relationship-driven storage can expand where it actually simplifies logic

## Final Recommendation

Adopt a single SQLite `state.db` as the source of truth for persisted application state, using a hybrid model:

- relational tables for identity, scheduling, grouping, and lookup
- protobuf JSON text payloads for forward-compatible domain payloads
- memory only for runtime objects and derived caches
- Pebble retained only for trie-like cache state that does not benefit from relational persistence; legacy flow and FakeIP data are startup-import sources only

This is the best balance between:

- actually using SQLite as a relational database
- keeping migration risk under control
- avoiding a giant schema explosion
- steadily simplifying the current in-memory document model
