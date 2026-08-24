package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func main() {
	source := flag.String("source", "", "source Go SQLite state database")
	output := flag.String("output", "", "new FTS-free SQLite snapshot for yuhaiin-rust")
	flag.Parse()
	if *source == "" || *output == "" {
		flag.Usage()
		os.Exit(2)
	}

	report, err := sqlite.ExportRustSnapshot(context.Background(), *source, *output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "yuhaiin-rust-export: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(
		"yuhaiin-rust-snapshot-ok schema=%s fakeip_rows=%d output_bytes=%d sha256=%s manifest=%s removed_fts=%v output=%s\n",
		report.SchemaVersion,
		report.FakeIPRows,
		report.OutputBytes,
		report.SnapshotSHA256,
		report.ManifestPath,
		report.RemovedVirtualTables,
		*output,
	)
}
