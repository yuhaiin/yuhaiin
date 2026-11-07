package recovery

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	testfixture "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	inbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	archive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
)

func TestRecoveryDependencyObligationsRoundTrip(t *testing.T) {
	for _, scenario := range []string{"disabled_inbound", "active_inbound", "disabled_node", "uninitialized_identities", "dynamic_library", "nebula_empty", "nebula_missing", "nebula_hardware", "missing_web", "inactive_metadata", "inactive_inbound_metadata", "removed_protocol_node", "removed_protocol_inbound"} {
		t.Run(scenario, func(t *testing.T) {
			source, key := testfixture.BasicDeployment(t)
			db, err := testfixture.OpenState(t.Context(), filepath.Join(source, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			missing := filepath.Join(t.TempDir(), "not-generated.pem")
			want := "missing_dependency"
			switch scenario {
			case "disabled_inbound", "active_inbound", "inactive_inbound_metadata":
				value := inbound.Inbound{ID: "listener", Name: "Listener", Enabled: scenario == "active_inbound",
					Network:    inbound.NewTypedNetwork(inbound.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: inbound.UDPDisabled}),
					Protocol:   inbound.NewTypedProtocol(inbound.HTTPProtocol{}),
					Transports: []inbound.Transport{inbound.NewTypedTransport(inbound.TLSTransport{TLS: &inbound.ServerTLSConfig{Certificates: []inbound.Certificate{{CertFile: missing, KeyFile: "site.key"}}}})}}
				err = store.NewInboundStore(db.DB()).Save(t.Context(), value, 0)
				if scenario == "inactive_inbound_metadata" {
					want = "inactive_inbound_configuration"
					if err == nil {
						_, err = db.DB().ExecContext(t.Context(), `UPDATE inbounds_v2 SET data_json=json_set(data_json,'$.authentication',json('{"mode":"obsolete"}')) WHERE id='listener'`)
					}
				}
			case "disabled_node":
				cfg, getErr := store.NewNodeStore(db.DB()).Get(t.Context(), "tls")
				if getErr != nil {
					t.Fatal(getErr)
				}
				cfg.Chain[0].TLSTermination.TLS.Certificates[0].CertFilePath = missing
				err = store.NewNodeStore(db.DB()).Save(t.Context(), cfg, 0)
			case "uninitialized_identities":
				want = "identity_not_initialized"
				for _, item := range []node.Node{
					{ID: "tail", Name: "Tail", Origin: "manual", Chain: []node.Protocol{{Type: "tailscale", Tailscale: &node.Tailscale{Hostname: "new-host", AuthKey: "fixture"}}}},
					{ID: "zt", Name: "ZT", Origin: "manual", Chain: []node.Protocol{{Type: "zerotier", ZeroTier: &node.ZeroTier{NetworkID: "8056c2e21c000001"}}}},
				} {
					if saveErr := store.NewNodeStore(db.DB()).Save(t.Context(), item, 0); saveErr != nil {
						t.Fatal(saveErr)
					}
				}
			case "dynamic_library":
				want = "external_runtime"
				err = store.NewNodeStore(db.DB()).Save(t.Context(), node.Node{ID: "extra", Name: "ZT", Origin: "manual", Chain: []node.Protocol{{Type: "zerotier", ZeroTier: &node.ZeroTier{NetworkID: "8056c2e21c000001", LibraryPath: missing}}}}, 0)
			case "nebula_empty", "nebula_missing", "nebula_hardware":
				want = "protocol_reconfiguration"
				raw := ""
				if scenario == "nebula_missing" {
					raw = "pki:\n  ca: site.crt\n  cert: absent.crt\n  key: site.key\n"
				}
				if scenario == "nebula_hardware" {
					raw = "pki:\n  ca: site.crt\n  cert: site.crt\n  key: 'pkcs11:token=hardware-fixture'\n"
				}
				err = store.NewNodeStore(db.DB()).Save(t.Context(), node.Node{ID: "extra", Name: "Nebula", Enabled: true, Origin: "manual", Chain: []node.Protocol{{Type: "nebula", Nebula: &node.Nebula{ConfigYAML: raw}}}}, 0)
			case "missing_web":
				want = "missing_web_assets"
				err = backupstore.New(db.DB()).RecordRecoveryRuntime(t.Context(), contractrecovery.Runtime{ManagementTLS: "self_signed", ManagementAuth: true, WorkingDirectory: source, ExternalWebDirectory: missing})
			case "removed_protocol_node":
				// An enabled node still carrying a protocol removed in an earlier
				// release, with a file reference the removed schema used to own.
				want = "protocol_reconfiguration"
				_, err = db.DB().ExecContext(t.Context(), `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES('legacy','Legacy','','manual',1,'[]',0,?)`,
					`{"id":"legacy","name":"Legacy","origin":"manual","enabled":true,"chain":[{"type":"http_termination","http_termination":{"tls":{"certificates":[{"cert_file_path":`+strconv.Quote(missing)+`,"key_file_path":"site.key"}]}}}]}`)
			case "removed_protocol_inbound":
				want = "protocol_reconfiguration"
				value := inbound.Inbound{ID: "listener", Name: "Listener", Enabled: true,
					Network:  inbound.NewTypedNetwork(inbound.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: inbound.UDPDisabled}),
					Protocol: inbound.NewTypedProtocol(inbound.HTTPProtocol{})}
				if err = store.NewInboundStore(db.DB()).Save(t.Context(), value, 0); err == nil {
					_, err = db.DB().ExecContext(t.Context(), `UPDATE inbounds_v2 SET data_json=json_set(data_json,'$.protocol',json('{"type":"reverse_http"}')) WHERE id='listener'`)
				}
			case "inactive_metadata":
				want = "inactive_node_configuration"
				_, err = db.DB().ExecContext(t.Context(), `UPDATE nodes_v2 SET data_json=json_set(data_json,'$.name','','$.latency',json('{"url":"obsolete"}')) WHERE id='tls'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "recovery.yhb")
			manifest, err := Create(t.Context(), source, output, archive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true})
			if err != nil {
				t.Fatal(err)
			}
			if !manifest.CompleteInventory || (manifest.Version != 3 && scenario != "uninitialized_identities") || !slices.ContainsFunc(manifest.Requirements, func(r contractrecovery.Requirement) bool { return r.Kind == want }) {
				t.Fatal("obligation absent or dishonest inventory", manifest)
			}
			encrypted, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encrypted, []byte(missing)) || bytes.Contains(encrypted, []byte("pkcs11:token")) {
				t.Fatal("archive metadata escaped encryption")
			}
			prepared, err := archive.Prepare(t.Context(), bytes.NewReader(encrypted), t.TempDir(), archive.Decryption{Identity: key.String()})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(prepared.Manifest.Requirements, manifest.Requirements) {
				t.Fatal("authenticated obligations changed")
			}
			if scenario == "disabled_inbound" {
				// An authenticated archive cannot use an optional-file warning
				// to satisfy a mandatory management startup input.
				inputs := *prepared.Manifest.Runtime
				inputs.ManagementTLS = "files"
				inputs.CertificateFile, inputs.KeyFile = missing, "site.key"
				prepared.Manifest.Runtime = &inputs
				if _, _, err := prepareRecoveryRestore(t.Context(), t.TempDir(), prepared, "original"); err == nil {
					t.Fatal("missing management TLS certificate accepted during preview")
				}
			}
			if err := prepared.Close(); err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{"original", "clone"} {
				t.Run(mode, func(t *testing.T) {
					target := t.TempDir()
					preview, err := Preview(t.Context(), target, bytes.NewReader(encrypted), archive.Decryption{Identity: key.String()}, mode)
					if err != nil {
						t.Fatal(err)
					}
					if !slices.Contains(preview.Warnings, want) {
						t.Fatal("preview omitted actionable obligation", preview.Warnings)
					}
					result, err := Restore(t.Context(), target, bytes.NewReader(encrypted), archive.Decryption{Identity: key.String()}, RestoreOptions{Mode: mode, ConfirmedMaintenance: true, ConfirmBackupID: manifest.ID, ConfirmSourceInstanceID: manifest.InstanceID, ConfirmTargetInstanceID: preview.TargetInstanceID, ConfirmSourceStopped: true, ConfirmCredentialRevival: true})
					if err != nil {
						t.Fatal(err)
					}
					if scenario == "missing_web" && result.Runtime.ExternalWebDirectory != "" {
						t.Fatal("missing web root left active")
					}
					restored, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(target, "state.db"))
					if err != nil {
						t.Fatal(err)
					}
					defer restored.Close()
					for _, table := range []string{"nodes_v2", "inbounds_v2", "gateway_configuration"} {
						rows, err := restored.QueryContext(t.Context(), "SELECT data_json FROM "+table)
						if err != nil {
							t.Fatal(err)
						}
						for rows.Next() {
							var raw string
							if err := rows.Scan(&raw); err != nil {
								t.Fatal(err)
							}
							if strings.Contains(raw, missing) || strings.Contains(raw, source+string(filepath.Separator)) {
								t.Fatal("source-machine dependency survived rebind", table)
							}
						}
						if err := rows.Err(); err != nil {
							t.Fatal(err)
						}
						if err := rows.Close(); err != nil {
							t.Fatal(err)
						}
					}
					if scenario == "nebula_empty" || scenario == "nebula_missing" || scenario == "nebula_hardware" || scenario == "dynamic_library" {
						var enabled bool
						if err := restored.QueryRowContext(t.Context(), "SELECT enabled FROM nodes_v2 WHERE id='extra'").Scan(&enabled); err != nil || enabled {
							t.Fatal("unavailable resource activated", err)
						}
					}
					if scenario == "active_inbound" {
						var enabled bool
						if err := restored.QueryRowContext(t.Context(), "SELECT enabled FROM inbounds_v2 WHERE id='listener'").Scan(&enabled); err != nil || enabled {
							t.Fatal("missing-certificate listener activated", err)
						}
					}
				})
			}
		})
	}
}

func TestRecoveryMissingRequiredAndUnsafeDependenciesStillFail(t *testing.T) {
	for _, fault := range []string{"management_key", "directory", "dangling_symlink", "dangling_parent", "web_symlink", "identity_symlink"} {
		t.Run(fault, func(t *testing.T) {
			source, key := testfixture.Deployment(t)
			switch fault {
			case "management_key":
				if err := os.Remove(filepath.Join(source, "management-tls.pem")); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Remove(filepath.Join(source, "site.crt")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(source, "site.crt"), 0700); err != nil {
					t.Fatal(err)
				}
			case "dangling_symlink":
				if err := os.Remove(filepath.Join(source, "site.crt")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(source, "absent"), filepath.Join(source, "site.crt")); err != nil {
					t.Fatal(err)
				}
			case "dangling_parent":
				if err := os.Remove(filepath.Join(source, "site.crt")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(source, "absent"), filepath.Join(source, "alias")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(source, "alias", "file"), filepath.Join(source, "site.crt")); err != nil {
					t.Fatal(err)
				}
			case "web_symlink":
				db, err := testfixture.OpenState(t.Context(), filepath.Join(source, "state.db"))
				if err != nil {
					t.Fatal(err)
				}
				if err := backupstore.New(db.DB()).RecordRecoveryRuntime(t.Context(), contractrecovery.Runtime{ManagementTLS: "self_signed", WorkingDirectory: source, ExternalWebDirectory: filepath.Join(source, "web")}); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), filepath.Join(source, "web")); err != nil {
					t.Fatal(err)
				}
			case "identity_symlink":
				name := filepath.Join(source, "tailscale/fixture-host/tailscaled.state")
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(source, "site.key"), name); err != nil {
					t.Fatal(err)
				}
			}
			_, err := Create(t.Context(), source, filepath.Join(t.TempDir(), "failed.yhb"), archive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true})
			if err == nil {
				t.Fatal("required or unsafe dependency was ignored")
			}
			stage, code := captureFailureDetails(err)
			if stage != "dependency_inventory" {
				t.Fatal("wrong failure stage", stage, code)
			}
			if fault == "management_key" && code != "required_file_missing" {
				t.Fatal("required file failure lost", code)
			}
		})
	}
	for _, err := range []error{os.ErrPermission, errors.New("unsafe symlink")} {
		if _, code := captureFailureDetails(err); code == "required_file_missing" {
			t.Fatal("unrelated errors relaxed")
		}
	}
}

func TestRecoveryDependencyReadErrorsAreNotAbsence(t *testing.T) {
	source, key := testfixture.BasicDeployment(t)
	name := filepath.Join(source, "site.key")
	if err := os.Chmod(name, 0); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chmod(name, 0600); err != nil {
			t.Error(err)
		}
	}()
	file, probe := os.Open(name)
	if probe == nil {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		t.Skip("test account can bypass file permissions")
	}
	_, err := Create(t.Context(), source, filepath.Join(t.TempDir(), "fail.yhb"), archive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true})
	stage, code := captureFailureDetails(err)
	if err == nil || stage != "dependency_inventory" || code != "permission_denied" {
		t.Fatal("permission error was treated as an optional missing file", stage, code, err)
	}
}
