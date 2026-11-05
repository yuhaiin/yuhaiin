package sqlite

// Token labels are operator-facing metadata only; they never participate in
// authentication. Existing credentials keep empty labels.
var managementTokenLabelsMigration = Migration{Version: 15, Name: "management_token_labels", Statements: []string{
	`ALTER TABLE management_credentials ADD COLUMN name TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE management_credentials ADD COLUMN note TEXT NOT NULL DEFAULT ''`,
}}
