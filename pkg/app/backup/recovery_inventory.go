package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	inboundcontract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	nodecontract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/nebula"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/zerotier"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

type recoveryInventory struct {
	ctx              context.Context
	source, snapshot string
	runtime          *contract.RecoveryRuntime
	manifest         *contract.RecoveryManifest
	copied           map[string]string
	bytes            int64
}

func newRecoveryInventory(ctx context.Context, source, snapshot string, inputs *contract.RecoveryRuntime, manifest *contract.RecoveryManifest) *recoveryInventory {
	return &recoveryInventory{ctx: ctx, source: source, snapshot: snapshot, runtime: inputs, manifest: manifest, copied: map[string]string{}}
}

func (c *recoveryInventory) collect(db *sql.DB) error {
	if err := backupstore.ValidateRecoveryRuntime(*c.runtime); err != nil {
		return err
	}
	for _, file := range c.manifest.Files {
		info, err := os.Stat(filepath.Join(c.snapshot, file.Path))
		if err != nil {
			return err
		}
		if info.Size() > backupstore.MaxRecoveryDataBytes-c.bytes {
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
		if err := c.fileReferences(node); err != nil {
			return fmt.Errorf("node %s dependencies: %w", node.ID, err)
		}
		return c.protocols(node.ID, node.Chain)
	}); err != nil {
		return err
	}
	if err := store.NewInboundStore(db).RangeForRecovery(c.ctx, func(inbound inboundcontract.Inbound) error { return c.fileReferences(inbound) }); err != nil {
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
		if err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
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
	slices.SortFunc(c.manifest.Files, func(a, b contract.RecoveryFile) int { return strings.Compare(a.Path, b.Path) })
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
			if err == nil && protocol.ZeroTier.LibraryPath != "" {
				_, err = c.copy(protocol.ZeroTier.LibraryPath, "dependency", false)
			}
		case protocol.Nebula != nil:
			paths, dependencyErr := nebula.RecoveryFiles(*protocol.Nebula)
			if dependencyErr != nil {
				return fmt.Errorf("nebula node %s recovery dependencies: %w", nodeID, dependencyErr)
			}
			for _, path := range paths {
				if _, err := c.copy(path, "dependency", false); err != nil {
					return err
				}
			}
		}
		if err != nil {
			return fmt.Errorf("node %s identity inventory: %w", nodeID, err)
		}
		if (protocol.Tailscale != nil || protocol.ZeroTier != nil) && len(files) == 0 {
			if len(c.manifest.Requirements) >= backupstore.MaxRecoveryFiles {
				return errors.New("too many recovery requirements")
			}
			c.manifest.Requirements = append(c.manifest.Requirements, contract.RecoveryRequirement{Kind: "identity_not_initialized", NodeID: nodeID})
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
						if _, err := c.copy(name, "dependency", false); err != nil {
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
	if len(c.manifest.Files) >= backupstore.MaxRecoveryFiles {
		return "", errors.New("recovery file count exceeds limit")
	}
	info, err := os.Stat(source)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("recovery dependency must be a regular file")
	}
	if info.Size() < 0 || info.Size() > backupstore.MaxRecoveryDataBytes-c.bytes {
		return "", errors.New("recovery dependencies exceed size budget")
	}
	relative, err := filepath.Rel(c.source, source)
	inside := err == nil && filepath.IsLocal(relative) && relative != "."
	archivePath := filepath.ToSlash(relative)
	original := ""
	if !inside {
		if owned {
			return "", errors.New("protocol-owned identity escaped its deployment directory")
		}
		digest := sha256.Sum256([]byte(source))
		archivePath = "dependencies/" + hex.EncodeToString(digest[:]) + ".bin"
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
	c.manifest.Files = append(c.manifest.Files, contract.RecoveryFile{Path: archivePath, Role: role, SourcePath: original})
	return archivePath, nil
}
