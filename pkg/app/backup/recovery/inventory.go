package recovery

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	inboundcontract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	nodecontract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/nebula"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/zerotier"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

type recoveryInventory struct {
	ctx              context.Context
	source, snapshot string
	runtime          *contractrecovery.Runtime
	manifest         *contractrecovery.Manifest
	copied           map[string]string
	requirements     map[contractrecovery.Requirement]bool
	bytes            int64
	checkSpace       func(string, int64) error
}

func newRecoveryInventory(ctx context.Context, source, snapshot string, inputs *contractrecovery.Runtime, manifest *contractrecovery.Manifest) *recoveryInventory {
	return &recoveryInventory{ctx: ctx, source: source, snapshot: snapshot, runtime: inputs, manifest: manifest, copied: map[string]string{}, requirements: map[contractrecovery.Requirement]bool{}}
}

func (c *recoveryInventory) collect(db *sql.DB) error {
	if err := backuparchive.ValidateRuntime(*c.runtime); err != nil {
		return err
	}
	for _, file := range c.manifest.Files {
		info, err := os.Stat(filepath.Join(c.snapshot, file.Path))
		if err != nil {
			return err
		}
		if info.Size() > backuparchive.MaxDataBytes-c.bytes {
			return errors.New("recovery database set exceeds size limit")
		}
		c.bytes += info.Size()
	}
	if !filepath.IsAbs(c.runtime.WorkingDirectory) {
		return errors.New("backup requires the deployment's absolute working directory")
	}
	switch c.runtime.ManagementTLS {
	case "disabled":
	case "self_signed":
		if _, err := c.copy(filepath.Join(c.source, "management-tls.pem"), "listener_certificate", true); err != nil {
			return err
		}
	case "managed":
		// The closed-writer SQLite snapshot owns site/account keys and material.
		resources := certificates.New(db)
		if _, err := resources.Get(c.ctx, c.runtime.ManagedCertificateID); err != nil {
			return errors.New("management certificate is absent from recovery snapshot")
		}
		if _, err := resources.Material(c.ctx, c.runtime.ManagedCertificateID); err != nil {
			return errors.New("management certificate material is absent from recovery snapshot")
		}
	case "files":
		if c.runtime.CertificateFile == "" || c.runtime.KeyFile == "" {
			return errors.New("management TLS file pair is incomplete")
		}
		for _, name := range []string{c.runtime.CertificateFile, c.runtime.KeyFile} {
			if _, err := c.copy(name, "listener_certificate", false); err != nil {
				return err
			}
		}
	default:
		return errors.New("unknown management TLS mode for recovery inventory")
	}
	if err := store.NewNodeStore(db).RangeForRecovery(c.ctx, func(node nodecontract.Node) error {
		if !node.Enabled && node.Validate() != nil {
			if err := c.requirement(contractrecovery.Requirement{Kind: "inactive_node_configuration", NodeID: node.ID}); err != nil {
				return err
			}
		}
		if err := c.fileReferences(node); err != nil {
			return fmt.Errorf("node %s dependencies: %w", node.ID, err)
		}
		return c.protocols(node.ID, node.Chain)
	}, func(resource store.UnsupportedResource) error {
		return c.unsupported("node", resource)
	}); err != nil {
		return err
	}
	if err := store.NewInboundStore(db).RangeForRecovery(c.ctx, func(inbound inboundcontract.Inbound) error {
		if !inbound.Enabled && inbound.Validate() != nil {
			if err := c.requirement(contractrecovery.Requirement{Kind: "inactive_inbound_configuration", NodeID: inbound.ID}); err != nil {
				return err
			}
		}
		return c.fileReferences(inbound)
	}, func(resource store.UnsupportedResource) error {
		return c.unsupported("inbound", resource)
	}); err != nil {
		return fmt.Errorf("inbound dependencies: %w", err)
	}
	gateway, err := store.NewGatewayStore(db).Load(c.ctx)
	if err != nil {
		return err
	}
	if err := c.fileReferences(gateway); err != nil {
		return fmt.Errorf("gateway dependencies: %w", err)
	}
	if c.runtime.ExternalWebDirectory != "" {
		directory := c.absolute(c.runtime.ExternalWebDirectory)
		relative, err := filepath.Rel(directory, c.source)
		if err == nil && filepath.IsLocal(relative) {
			return errors.New("external web assets cannot contain the deployment data directory")
		}
		if err := missingDependency(directory); errors.Is(err, os.ErrNotExist) {
			if err := c.requirement(contractrecovery.Requirement{Kind: "missing_web_assets", Path: directory}); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
			if cancelErr := c.ctx.Err(); cancelErr != nil {
				return cancelErr
			}
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("external web assets contain a symlink; materialize the assets before backup")
			}
			if entry.IsDir() {
				return nil
			}
			_, err = c.copy(path, "dependency", false)
			return err
		}); err != nil {
			return fmt.Errorf("external web assets: %w", err)
		}
	}
	slices.SortFunc(c.manifest.Files, func(a, b contractrecovery.File) int { return strings.Compare(a.Path, b.Path) })
	slices.SortFunc(c.manifest.Requirements, func(a, b contractrecovery.Requirement) int {
		if order := strings.Compare(a.Kind, b.Kind); order != 0 {
			return order
		}
		if order := strings.Compare(a.NodeID, b.NodeID); order != 0 {
			return order
		}
		return strings.Compare(a.Path, b.Path)
	})
	return nil
}

// unsupported keeps a resource the current schema cannot use, for example one
// still carrying a removed protocol. The running service already skips it, so
// it cannot block recovery; its raw document stays in the configuration
// database and is marked for reconfiguration. Known file references are still
// inventoried so a restore can rebind them. Credentials owned by an unknown
// protocol cannot be located, which the requirement records.
func (c *recoveryInventory) unsupported(kind string, resource store.UnsupportedResource) error {
	log.Warn("recovery backup keeps unsupported stored resource for reconfiguration", "kind", kind, "id", resource.ID, "err", resource.Err)
	if err := c.requirement(contractrecovery.Requirement{Kind: "protocol_reconfiguration", NodeID: resource.ID}); err != nil {
		return err
	}
	if err := c.fileReferences(resource.Document); err != nil {
		return fmt.Errorf("%s %s dependencies: %w", kind, resource.ID, err)
	}
	return nil
}

func (c *recoveryInventory) protocols(nodeID string, chain []nodecontract.Protocol) error {
	for _, protocol := range chain {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		var files []string
		var err error
		switch {
		case protocol.Tailscale != nil:
			files, err = tailscale.RecoveryFiles(c.source, *protocol.Tailscale)
		case protocol.ZeroTier != nil:
			files, err = zerotier.RecoveryFiles(c.source, *protocol.ZeroTier)
		case protocol.Nebula != nil:
			inventory, dependencyErr := nebula.RecoveryInventory(*protocol.Nebula)
			paths := inventory.Files
			if dependencyErr != nil {
				return fmt.Errorf("nebula node %s recovery dependencies: %w", nodeID, dependencyErr)
			}
			if inventory.NeedsReconfiguration {
				if err := c.requirement(contractrecovery.Requirement{Kind: "protocol_reconfiguration", NodeID: nodeID}); err != nil {
					return err
				}
			}
			for _, path := range paths {
				missing, err := c.configuredFile(path)
				if err != nil {
					return err
				}
				if missing {
					if err := c.requirement(contractrecovery.Requirement{Kind: "protocol_reconfiguration", NodeID: nodeID}); err != nil {
						return err
					}
				}
			}
		}
		if err != nil {
			return fmt.Errorf("node %s identity inventory: %w", nodeID, err)
		}
		if (protocol.Tailscale != nil || protocol.ZeroTier != nil) && len(files) == 0 {
			if err := c.requirement(contractrecovery.Requirement{Kind: "identity_not_initialized", NodeID: nodeID}); err != nil {
				return err
			}
		}
		for _, path := range files {
			if _, err := c.copy(path, "protocol_identity", true); err != nil {
				return err
			}
		}
		if protocol.NetworkSplit != nil {
			for _, child := range []*nodecontract.Protocol{protocol.NetworkSplit.TCP, protocol.NetworkSplit.UDP} {
				if child != nil {
					if err := c.protocols(nodeID, []nodecontract.Protocol{*child}); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// Decode the typed documents back to JSON only to walk the small set of actual
// file-reference fields. URLs, websocket paths and inline key bytes are not file
// dependencies. Protocol-owned persistent identities are handled separately.
func (c *recoveryInventory) fileReferences(document any) error {
	data, err := json.Marshal(document)
	if err != nil {
		return err
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	var walk func(any) error
	walk = func(value any) error {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				if isRecoveryFileReference(key) {
					name, ok := child.(string)
					if ok && name != "" {
						if key == "library_path" {
							if err := c.requirement(contractrecovery.Requirement{Kind: "external_runtime", Path: c.absolute(name)}); err != nil {
								return err
							}
						} else if _, err := c.configuredFile(name); err != nil {
							return err
						}
					}
				}
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range value {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value)
}

func isRecoveryFileReference(key string) bool {
	return slices.Contains([]string{"cert_file_path", "key_file_path", "certFile", "keyFile", "certificateFile", "library_path"}, key)
}

func (c *recoveryInventory) absolute(name string) string {
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	return filepath.Join(c.runtime.WorkingDirectory, name)
}

func (c *recoveryInventory) copy(name, role string, owned bool) (string, error) {
	if err := c.ctx.Err(); err != nil {
		return "", err
	}
	source := c.absolute(name)
	if path, ok := c.copied[source]; ok {
		return path, nil
	}
	if c.requirements[contractrecovery.Requirement{Kind: "missing_dependency", Path: source}] {
		return "", errors.New("dependency appeared after absence was inventoried")
	}
	if len(c.manifest.Files) >= backuparchive.MaxFiles {
		return "", errors.New("recovery file count exceeds limit")
	}
	info, err := os.Stat(source)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("recovery dependency must be a regular file")
	}
	if info.Size() < 0 || info.Size() > backuparchive.MaxDataBytes-c.bytes {
		return "", errors.New("recovery dependencies exceed size budget")
	}
	if err := c.checkSpace(c.snapshot, info.Size()); err != nil {
		return "", err
	}
	relative, err := filepath.Rel(c.source, source)
	inside := err == nil && filepath.IsLocal(relative) && relative != "."
	archivePath := filepath.ToSlash(relative)
	original := ""
	if !inside {
		if owned {
			return "", errors.New("protocol-owned identity escaped its deployment directory")
		}
		archivePath = recoveryDependencyPath(source)
		original = source
	}
	if owned {
		root, err := os.OpenRoot(c.source)
		if err != nil {
			return "", err
		}
		sourceInfo, err := root.Lstat(filepath.FromSlash(archivePath))
		_ = root.Close()
		if err != nil {
			return "", err
		}
		if !sourceInfo.Mode().IsRegular() {
			return "", errors.New("protocol identity source cannot be a symlink")
		}
	}
	root, err := os.OpenRoot(c.snapshot)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err := root.MkdirAll(filepath.Dir(filepath.FromSlash(archivePath)), 0o700); err != nil {
		return "", err
	}
	output, err := root.OpenFile(filepath.FromSlash(archivePath), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	input, err := os.Open(source)
	if err != nil {
		_ = output.Close()
		return "", err
	}
	opened, err := input.Stat()
	if err != nil || !os.SameFile(opened, info) {
		_ = input.Close()
		_ = output.Close()
		return "", errors.New("backup dependency changed while opening")
	}
	buffer := make([]byte, 32<<10)
	remaining := info.Size()
	for remaining > 0 {
		if err := c.ctx.Err(); err != nil {
			_ = input.Close()
			_ = output.Close()
			return "", err
		}
		n, readErr := input.Read(buffer[:min(int64(len(buffer)), remaining)])
		if n > 0 {
			if _, err := output.Write(buffer[:n]); err != nil {
				_ = input.Close()
				_ = output.Close()
				return "", err
			}
			remaining -= int64(n)
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) || remaining != 0 {
				_ = input.Close()
				_ = output.Close()
				return "", io.ErrUnexpectedEOF
			}
		}
	}
	after, statErr := input.Stat()
	closeErr := input.Close()
	if statErr != nil || closeErr != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		_ = output.Close()
		return "", errors.New("backup dependency changed while copying")
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return "", err
	}
	if err := output.Close(); err != nil {
		return "", err
	}
	c.bytes += info.Size()
	c.copied[source] = archivePath
	c.manifest.Files = append(c.manifest.Files, contractrecovery.File{Path: archivePath, Role: role, SourcePath: original})
	return archivePath, nil
}

// Configured certificate references may be dormant, generated later, or have
// inline fallbacks. Account for absence, but never downgrade read/copy failures.
func (c *recoveryInventory) configuredFile(name string) (bool, error) {
	source := c.absolute(name)
	if _, exists := c.copied[source]; exists {
		return false, nil
	}
	if c.requirements[contractrecovery.Requirement{Kind: "missing_dependency", Path: source}] {
		return true, nil
	}
	if err := missingDependency(source); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		return true, c.requirement(contractrecovery.Requirement{Kind: "missing_dependency", Path: source})
	}
	_, err := c.copy(name, "dependency", false)
	return false, err
}

// An absent leaf below real directories is different from a dangling symlink.
// Existing certificate symlinks remain materialized by copy, as before.
func missingDependency(name string) error {
	for current := name; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				if _, err := os.Stat(current); err != nil {
					return fmt.Errorf("unresolved dependency symlink: %v", err)
				}
			}
			if current == name {
				return nil
			}
			return os.ErrNotExist
		}
		if !errors.Is(err, os.ErrNotExist) || filepath.Dir(current) == current {
			return err
		}
	}
}

func (c *recoveryInventory) requirement(item contractrecovery.Requirement) error {
	if c.requirements[item] {
		return nil
	}
	if len(c.manifest.Requirements) >= backuparchive.MaxFiles {
		return errors.New("too many recovery requirements")
	}
	c.requirements[item] = true
	c.manifest.Requirements = append(c.manifest.Requirements, item)
	return nil
}
