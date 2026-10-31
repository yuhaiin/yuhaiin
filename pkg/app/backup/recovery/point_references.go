package recovery

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"

	inboundcontract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	nodecontract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/nebula"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

// A saved node/listener may intentionally use a file in an old copy. Preserve
// such copies, including aliases and Nebula's inline file references. This is a
// bounded startup/maintenance read, never a forwarding operation or new store.
func pinConfiguredPoints(ctx context.Context, directory string, pins map[string]bool) error {
	db, err := sqlite.OpenLiveReader(ctx, filepath.Join(directory, "state.db"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer db.Close()
	workingDirectory := directory
	inputs, err := backupstore.LoadRecoveryRuntime(ctx, db)
	if err != nil {
		return err
	}
	if inputs != nil {
		workingDirectory = inputs.WorkingDirectory
	}
	mark := func(value string) {
		for _, prefix := range []string{".recovery-point-", ".recovery-pruning-"} {
			remaining := value
			for {
				_, rest, found := strings.Cut(remaining, prefix)
				if !found {
					break
				}
				if len(rest) >= 36 && validPointID(rest[:36]) {
					pins[rest[:36]] = true
				}
				remaining = rest
			}
		}
	}

	markPath := func(value string) {
		if value == "" {
			return
		}
		mark(value)
		if !filepath.IsAbs(value) {
			value = filepath.Join(workingDirectory, value)
		}
		if resolved, err := filepath.EvalSymlinks(value); err == nil {
			mark(resolved)
		}
	}
	if inputs != nil {
		markPath(inputs.WorkingDirectory)
		markPath(inputs.CertificateFile)
		markPath(inputs.KeyFile)
		markPath(inputs.ExternalWebDirectory)
	}
	var walk func(any) error
	walk = func(value any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				if text, ok := child.(string); ok && isRecoveryFileReference(key) {
					markPath(text)
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
		case string:
			mark(value)
		}
		return nil
	}
	document := func(value any) error {
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		var tree any
		if err := json.Unmarshal(data, &tree); err != nil {
			return err
		}
		return walk(tree)
	}
	var protocols func([]nodecontract.Protocol) error
	protocols = func(chain []nodecontract.Protocol) error {
		for _, protocol := range chain {
			if protocol.Nebula != nil {
				files, err := nebula.RecoveryFiles(*protocol.Nebula)
				if err != nil {
					return err
				}
				for _, name := range files {
					markPath(name)
				}
			}
			if protocol.NetworkSplit != nil {
				for _, child := range []*nodecontract.Protocol{protocol.NetworkSplit.TCP, protocol.NetworkSplit.UDP} {
					if child != nil {
						if err := protocols([]nodecontract.Protocol{*child}); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	}
	if err := store.NewNodeStore(db).RangeForRecovery(ctx, func(node nodecontract.Node) error {
		if err := document(node); err != nil {
			return err
		}
		return protocols(node.Chain)
	}); err != nil {
		return err
	}
	if err := store.NewInboundStore(db).RangeForRecovery(ctx, func(inbound inboundcontract.Inbound) error { return document(inbound) }); err != nil {
		return err
	}
	gateway, err := store.NewGatewayStore(db).Load(ctx)
	if err != nil {
		return err
	}
	return document(gateway)
}
