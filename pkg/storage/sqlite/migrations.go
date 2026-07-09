package sqlite

type Migration struct {
	Version    int
	Name       string
	Statements []string
}

var migrations = []Migration{
	{
		Version: 1,
		Name:    "initial_schema",
		Statements: []string{
			`CREATE TABLE android_extra_preferences (
				key         TEXT PRIMARY KEY,
				value_json  TEXT NOT NULL,
				updated_at  INTEGER NOT NULL,
				CHECK (json_valid(value_json))
			)`,
			`CREATE INDEX android_extra_preferences_updated_at_idx
			ON android_extra_preferences(updated_at)`,
			`CREATE TABLE settings_kv (
				section      TEXT NOT NULL,
				key          TEXT NOT NULL,
				value_json   TEXT NOT NULL CHECK (json_valid(value_json)),
				updated_at   INTEGER NOT NULL,
				PRIMARY KEY (section, key)
			)`,
			`CREATE INDEX settings_kv_section_idx ON settings_kv(section)`,
			`CREATE TABLE dns_settings (
				id                       INTEGER PRIMARY KEY CHECK (id = 1),
				server                   TEXT NOT NULL DEFAULT '',
				fakedns_enabled          INTEGER NOT NULL,
				fakedns_ipv4_range       TEXT NOT NULL DEFAULT '',
				fakedns_ipv6_range       TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE TABLE dns_resolvers (
				name             TEXT PRIMARY KEY,
				resolver_type    INTEGER NOT NULL,
				host             TEXT NOT NULL,
				subnet           TEXT NOT NULL DEFAULT '',
				tls_servername   TEXT NOT NULL DEFAULT '',
				data_json        TEXT NOT NULL CHECK (json_valid(data_json))
			)`,
			`CREATE TABLE dns_hosts (
				host    TEXT PRIMARY KEY,
				target  TEXT NOT NULL
			)`,
			`CREATE TABLE dns_fakedns_lists (
				kind    TEXT NOT NULL,
				value   TEXT NOT NULL,
				PRIMARY KEY (kind, value)
			)`,
			`CREATE TABLE inbound_settings (
				id                 INTEGER PRIMARY KEY CHECK (id = 1),
				hijack_dns         INTEGER NOT NULL,
				hijack_dns_fakeip  INTEGER NOT NULL,
				sniff_enabled      INTEGER NOT NULL
			)`,
			`CREATE TABLE inbounds (
				name          TEXT PRIMARY KEY,
				enabled       INTEGER NOT NULL,
				inbound_type  TEXT NOT NULL,
				listen_host   TEXT NOT NULL DEFAULT '',
				updated_at    INTEGER NOT NULL,
				data_json     TEXT NOT NULL CHECK (json_valid(data_json))
			)`,
			`CREATE INDEX inbounds_enabled_idx ON inbounds(enabled)`,
			`CREATE INDEX inbounds_type_idx ON inbounds(inbound_type)`,
			`CREATE TABLE nodes (
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
			)`,
			`CREATE INDEX nodes_group_name_idx ON nodes(group_name, name)`,
			`CREATE INDEX nodes_origin_idx ON nodes(origin)`,
			`CREATE UNIQUE INDEX nodes_selected_tcp_one ON nodes(selected_tcp) WHERE selected_tcp = 1`,
			`CREATE UNIQUE INDEX nodes_selected_udp_one ON nodes(selected_udp) WHERE selected_udp = 1`,
			`CREATE VIRTUAL TABLE nodes_fts USING fts5(
				name,
				group_name,
				search_text,
				content='nodes',
				content_rowid='id'
			)`,
			`CREATE TABLE node_tags (
				tag_name      TEXT NOT NULL,
				target_kind   TEXT NOT NULL CHECK (target_kind IN ('node', 'tag')),
				target_id     TEXT NOT NULL,
				updated_at    INTEGER NOT NULL,
				PRIMARY KEY (tag_name, target_kind, target_id),
				CHECK (tag_name <> target_id OR target_kind <> 'tag')
			)`,
			`CREATE INDEX node_tags_target_idx ON node_tags(target_kind, target_id)`,
			`CREATE TABLE subscriptions (
				name          TEXT PRIMARY KEY,
				updated_at    INTEGER NOT NULL,
				data_json     TEXT NOT NULL CHECK (json_valid(data_json))
			)`,
			`CREATE TABLE publishes (
				name          TEXT PRIMARY KEY,
				updated_at    INTEGER NOT NULL,
				data_json     TEXT NOT NULL CHECK (json_valid(data_json))
			)`,
			`CREATE TABLE route_settings (
				id                INTEGER PRIMARY KEY CHECK (id = 1),
				direct_resolver   TEXT NOT NULL DEFAULT '',
				proxy_resolver    TEXT NOT NULL DEFAULT '',
				resolve_locally   INTEGER NOT NULL,
				udp_proxy_fqdn    INTEGER NOT NULL
			)`,
			`CREATE TABLE route_rules (
				id           INTEGER PRIMARY KEY AUTOINCREMENT,
				name         TEXT NOT NULL UNIQUE,
				priority     INTEGER NOT NULL,
				disabled     INTEGER NOT NULL,
				updated_at   INTEGER NOT NULL,
				data_json    TEXT NOT NULL CHECK (json_valid(data_json))
			)`,
			`CREATE UNIQUE INDEX route_rules_priority_idx ON route_rules(priority)`,
			`CREATE TABLE route_lists (
				name         TEXT PRIMARY KEY,
				kind         TEXT NOT NULL DEFAULT '',
				updated_at   INTEGER NOT NULL,
				data_json    TEXT NOT NULL CHECK (json_valid(data_json))
			)`,
			`CREATE TABLE route_list_refresh (
				name               TEXT PRIMARY KEY,
				refresh_interval   INTEGER NOT NULL,
				last_refresh_time  INTEGER NOT NULL DEFAULT 0,
				last_error         TEXT NOT NULL DEFAULT '',
				FOREIGN KEY (name) REFERENCES route_lists(name) ON DELETE CASCADE
			)`,
			`CREATE INDEX route_list_refresh_due_idx
			ON route_list_refresh(refresh_interval, last_refresh_time)`,
			`CREATE TABLE backup_settings (
				id          INTEGER PRIMARY KEY CHECK (id = 1),
				updated_at  INTEGER NOT NULL,
				data_json   TEXT NOT NULL CHECK (json_valid(data_json))
			)`,
			`CREATE TABLE statistics_kv (
				key         TEXT PRIMARY KEY CHECK (key IN ('total_download', 'total_upload')),
				value_int   INTEGER NOT NULL,
				updated_at  INTEGER NOT NULL
			)`,
			`CREATE TABLE traffic_hourly (
				bucket_start_utc  INTEGER PRIMARY KEY,
				upload_bytes      INTEGER NOT NULL DEFAULT 0,
				download_bytes    INTEGER NOT NULL DEFAULT 0,
				updated_at        INTEGER NOT NULL
			)`,
			`CREATE TABLE connection_sessions (
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
			)`,
			`CREATE INDEX connection_sessions_state_idx
			ON connection_sessions(state, last_seen_at DESC)`,
			`CREATE INDEX connection_sessions_opened_at_idx
			ON connection_sessions(opened_at DESC)`,
			`CREATE TABLE connection_history (
				protocol             INTEGER NOT NULL,
				addr                 TEXT NOT NULL,
				process_name         TEXT NOT NULL DEFAULT '',
				hit_count            INTEGER NOT NULL,
				last_seen_at         INTEGER NOT NULL,
				last_connection_json TEXT NOT NULL CHECK (json_valid(last_connection_json)),
				PRIMARY KEY (protocol, addr, process_name)
			)`,
			`CREATE INDEX connection_history_last_seen_idx
			ON connection_history(last_seen_at DESC)`,
			`CREATE TABLE failed_connection_history (
				protocol       INTEGER NOT NULL,
				host           TEXT NOT NULL,
				process_name   TEXT NOT NULL DEFAULT '',
				failed_count   INTEGER NOT NULL,
				last_seen_at   INTEGER NOT NULL,
				last_error     TEXT NOT NULL DEFAULT '',
				PRIMARY KEY (protocol, host, process_name)
			)`,
			`CREATE INDEX failed_connection_history_last_seen_idx
			ON failed_connection_history(last_seen_at DESC)`,
		},
	},
	{
		Version: 2,
		Name:    "fakeip_cache",
		Statements: []string{
			`CREATE TABLE fakeip_entries (
				family        INTEGER NOT NULL,
				prefix        TEXT NOT NULL,
				domain        TEXT NOT NULL,
				ip            BLOB NOT NULL,
				created_at    INTEGER NOT NULL,
				last_used_at  INTEGER NOT NULL,
				PRIMARY KEY (family, prefix, domain),
				UNIQUE (family, prefix, ip)
			)`,
			`CREATE INDEX fakeip_entries_ip_idx
			ON fakeip_entries(family, prefix, ip)`,
			`CREATE INDEX fakeip_entries_lru_idx
			ON fakeip_entries(family, prefix, last_used_at)`,
			`CREATE TABLE fakeip_cursors (
				family        INTEGER NOT NULL,
				prefix        TEXT NOT NULL,
				cursor_ip     BLOB NOT NULL,
				cursor_idx    INTEGER NOT NULL,
				updated_at    INTEGER NOT NULL,
				PRIMARY KEY (family, prefix)
			)`,
		},
	},
	{
		Version: 3,
		Name:    "plain_contract_model",
		Statements: []string{
			`CREATE TABLE settings_json (
				id          INTEGER PRIMARY KEY CHECK (id = 1),
				version     INTEGER NOT NULL,
				data_json   TEXT NOT NULL CHECK (json_valid(data_json)),
				updated_at  INTEGER NOT NULL
			)`,
			`CREATE TABLE inbounds_v2 (
				id                    TEXT PRIMARY KEY,
				name                  TEXT NOT NULL DEFAULT '',
				enabled               INTEGER NOT NULL,
				network_type          TEXT NOT NULL,
				protocol_type         TEXT NOT NULL,
				transport_types_json  TEXT NOT NULL CHECK (json_valid(transport_types_json)),
				updated_at            INTEGER NOT NULL,
				data_json             TEXT NOT NULL CHECK (json_valid(data_json))
			)`,
			`CREATE INDEX inbounds_v2_enabled_idx
			ON inbounds_v2(enabled)`,
			`CREATE INDEX inbounds_v2_protocol_idx
			ON inbounds_v2(protocol_type)`,
			`CREATE INDEX inbounds_v2_network_idx
			ON inbounds_v2(network_type)`,
			`CREATE TABLE nodes_v2 (
				id                TEXT PRIMARY KEY,
				name              TEXT NOT NULL,
				group_name        TEXT NOT NULL,
				origin            TEXT NOT NULL,
				enabled           INTEGER NOT NULL,
				chain_types_json  TEXT NOT NULL CHECK (json_valid(chain_types_json)),
				updated_at        INTEGER NOT NULL,
				data_json         TEXT NOT NULL CHECK (json_valid(data_json))
			)`,
			`CREATE INDEX nodes_v2_group_name_idx
			ON nodes_v2(group_name, name)`,
			`CREATE INDEX nodes_v2_origin_idx
			ON nodes_v2(origin)`,
			`CREATE TABLE node_tags_v2 (
				id            TEXT PRIMARY KEY,
				name          TEXT NOT NULL,
				members_json  TEXT NOT NULL CHECK (json_valid(members_json)),
				updated_at    INTEGER NOT NULL
			)`,
			`CREATE UNIQUE INDEX node_tags_v2_name_idx
			ON node_tags_v2(name)`,
			`CREATE TABLE resolvers_v2 (
				id             TEXT PRIMARY KEY,
				resolver_type  TEXT NOT NULL,
				host           TEXT NOT NULL,
				updated_at     INTEGER NOT NULL,
				data_json      TEXT NOT NULL CHECK (json_valid(data_json))
			)`,
			`CREATE INDEX resolvers_v2_type_idx
			ON resolvers_v2(resolver_type)`,
			`CREATE TABLE route_rules_v2 (
				id           TEXT PRIMARY KEY,
				name         TEXT NOT NULL,
				priority     INTEGER NOT NULL,
				disabled     INTEGER NOT NULL,
				action_mode  TEXT NOT NULL,
				match_type   TEXT NOT NULL,
				tag          TEXT NOT NULL DEFAULT '',
				updated_at   INTEGER NOT NULL,
				data_json    TEXT NOT NULL CHECK (json_valid(data_json))
			)`,
			`CREATE UNIQUE INDEX route_rules_v2_name_idx
			ON route_rules_v2(name)`,
			`CREATE UNIQUE INDEX route_rules_v2_priority_idx
			ON route_rules_v2(priority)`,
		},
	},
	{
		Version: 4,
		Name:    "plain_route_lists",
		Statements: []string{
			`CREATE TABLE route_lists_v2 (
				name         TEXT PRIMARY KEY,
				list_type    TEXT NOT NULL DEFAULT '',
				source_type  TEXT NOT NULL DEFAULT '',
				updated_at   INTEGER NOT NULL,
				data_json    TEXT NOT NULL CHECK (json_valid(data_json))
			)`,
			`CREATE INDEX route_lists_v2_type_idx
			ON route_lists_v2(list_type, source_type)`,
		},
	},
}
