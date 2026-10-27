package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	nodecontract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
)

func recoveryAbsolute(workingDirectory, name string) string {
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	return filepath.Join(workingDirectory, name)
}

type recoveryProjection struct {
	files   map[string]string // confined destination -> original archive path
	sources map[string]string // original absolute reference -> confined destination
	web     string
}

func projectRecoveryFiles(manifest contract.RecoveryManifest) (recoveryProjection, error) {
	projection := recoveryProjection{files: map[string]string{}, sources: map[string]string{}}
	webSource := ""
	if manifest.Runtime.ExternalWebDirectory != "" {
		webSource = recoveryAbsolute(manifest.Runtime.WorkingDirectory, manifest.Runtime.ExternalWebDirectory)
		if relative, err := filepath.Rel(webSource, manifest.SourceDirectory); err == nil && filepath.IsLocal(relative) {
			return projection, errors.New("recovery web assets cannot contain the deployment directory")
		}
		relative, err := filepath.Rel(manifest.SourceDirectory, webSource)
		if err == nil && filepath.IsLocal(relative) && relative != "." {
			projection.web = filepath.ToSlash(relative)
		} else {
			digest := sha256.Sum256([]byte(webSource))
			projection.web = "dependencies/web/" + hex.EncodeToString(digest[:16])
		}
	}
	for _, file := range manifest.Files {
		original := filepath.Join(manifest.SourceDirectory, filepath.FromSlash(file.Path))
		if file.SourcePath != "" {
			original = filepath.Clean(file.SourcePath)
		}
		destination := file.Path
		if webSource != "" && (file.Role == "dependency" || file.Role == "listener_certificate") {
			relative, err := filepath.Rel(webSource, original)
			if err == nil && filepath.IsLocal(relative) && relative != "." {
				destination = filepath.ToSlash(filepath.Join(projection.web, relative))
			}
		}
		if err := backuparchive.ValidateDestination(destination); err != nil {
			return projection, err
		}
		if _, duplicate := projection.files[destination]; duplicate {
			return projection, errors.New("recovery file rebinding collides")
		}
		projection.files[destination] = file.Path
		projection.sources[original] = destination
	}
	return projection, nil
}

func relocateRecoveryFiles(directory string, files map[string]string) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	for destination, original := range files {
		if original == destination {
			continue
		}
		if _, exists := files[original]; exists {
			return errors.New("recovery projection would overwrite another archive source")
		}
		if err := root.MkdirAll(filepath.Dir(filepath.FromSlash(destination)), 0o700); err != nil {
			return err
		}
		if err := root.Rename(filepath.FromSlash(original), filepath.FromSlash(destination)); err != nil {
			return err
		}
	}
	return nil
}

func projectRecoveryTailnetIdentities(ctx context.Context, stage string, manifest contract.RecoveryManifest, projection *recoveryProjection) error {
	db, err := sqlite.OpenSnapshotReader(ctx, filepath.Join(stage, "state.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	assigned := map[string]string{}
	var walk func([]nodecontract.Protocol) error
	walk = func(chain []nodecontract.Protocol) error {
		for _, protocol := range chain {
			if err := ctx.Err(); err != nil {
				return err
			}
			if protocol.Tailscale != nil {
				input := *protocol.Tailscale
				directory, err := tailscale.RecoveryDirectory(manifest.SourceDirectory, input)
				if err != nil {
					return err
				}
				relative, err := filepath.Rel(manifest.SourceDirectory, directory)
				if err != nil || !filepath.IsLocal(relative) {
					return errors.New("tailnet recovery namespace escaped deployment")
				}
				legacy := "tailscale"
				if input.Hostname != "" {
					if filepath.Base(input.Hostname) != input.Hostname || input.Hostname == "." || input.Hostname == ".." {
						return errors.New("invalid legacy Tailnet recovery namespace")
					}
					legacy = filepath.Join(legacy, input.Hostname)
				}
				for _, name := range []string{"lite.json", "tailscaled.state"} {
					old := filepath.ToSlash(filepath.Join(legacy, name))
					current := filepath.ToSlash(filepath.Join(relative, name))
					if _, exists := projection.files[old]; !exists || old == current {
						continue
					}
					if previous, exists := assigned[old]; exists && previous != current {
						return errors.New("legacy Tailnet identity is ambiguous between configured nodes")
					}
					if _, exists := projection.files[current]; exists {
						return errors.New("archive contains competing current and legacy Tailnet identities")
					}
					assigned[old] = current
				}
			}
			if protocol.NetworkSplit != nil {
				for _, child := range []*nodecontract.Protocol{protocol.NetworkSplit.TCP, protocol.NetworkSplit.UDP} {
					if child != nil {
						if err := walk([]nodecontract.Protocol{*child}); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	}
	if err := store.NewNodeStore(db).RangeForRecovery(ctx, func(node nodecontract.Node) error { return walk(node.Chain) }); err != nil {
		return err
	}
	for old, destination := range assigned {
		projection.files[destination] = projection.files[old]
		delete(projection.files, old)
		projection.sources[filepath.Join(manifest.SourceDirectory, filepath.FromSlash(old))] = destination
	}
	return nil
}
