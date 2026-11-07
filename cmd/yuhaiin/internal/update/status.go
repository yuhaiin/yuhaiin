package updatecmd

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"io"
	"os"
	"runtime"
	"time"

	buildversion "github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
)

type adoptionStatus struct {
	SHA256        string                       `json:"sha256"`
	Size          int64                        `json:"size"`
	Compatibility contract.CompatibilityStatus `json:"compatibility"`
	AdoptedAt     time.Time                    `json:"adoptedAt"`
}

type operationReport struct {
	contract.OperationStatus
	Adoption  *adoptionStatus `json:"adoption,omitempty"`
	NextSteps []string        `json:"nextSteps,omitempty"`
}

func Status(args []string) error { return executeUpdateStatus(args, os.Stdout) }
func executeUpdateStatus(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("update-status", flag.ContinueOnError)
	directory := flags.String("path", configuration.DataDir.Load(), "deployment data directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected update-status arguments")
	}
	record, err := maintenance.Read(*directory)
	if err != nil {
		return err
	}
	if record == nil {
		return json.MarshalWrite(output, struct {
			State string `json:"state"`
		}{"no_operation"})
	}
	report := operationReport{OperationStatus: record.OperationStatus}
	if record.Phase == "failed" || record.Phase == "manual_recovery" {
		report.NextSteps = maintenance.RecoverySteps(*directory, record)
	}
	// A stale or unreadable adoption never grants startup; only report a
	// valid record bound to this operation.
	if a, err := maintenance.ReadAdoption(*directory); err == nil && a != nil && a.OperationID == record.ID {
		report.Adoption = &adoptionStatus{SHA256: a.Executable.SHA256, Size: a.Executable.Size, Compatibility: a.Compatibility, AdoptedAt: a.AdoptedAt}
	}
	return json.MarshalWrite(output, report)
}

// Adopt is the explicit operator handoff after a preparation failure and a
// manual executable replacement. It must run from the installed executable.
func Adopt(args []string) error { return executeUpdateAdopt(args, os.Stdout) }
func executeUpdateAdopt(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("update-adopt", flag.ContinueOnError)
	directory := flags.String("path", configuration.DataDir.Load(), "deployment data directory")
	dryRun := flags.Bool("dry-run", false, "only verify the installed executable and schemas; record nothing")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected update-adopt arguments")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	architecture := buildversion.ReleaseArch
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	a, err := maintenance.Adopt(ctx, *directory, maintenance.AdoptOptions{Executable: executable, Platform: runtime.GOOS, Architecture: architecture, DryRun: *dryRun})
	if err != nil {
		return err
	}
	return json.MarshalWrite(output, struct {
		State         string                       `json:"state"`
		OperationID   string                       `json:"operationId"`
		SHA256        string                       `json:"sha256"`
		Compatibility contract.CompatibilityStatus `json:"compatibility"`
	}{map[bool]string{true: "verified_not_recorded", false: "adopted"}[*dryRun], a.OperationID, a.Executable.SHA256, a.Compatibility})
}
