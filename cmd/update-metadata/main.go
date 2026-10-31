// update-metadata runs on the build host; it never executes the target binary.
package main

import (
	"context"
	"encoding/json/v2"
	"flag"
	"fmt"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicfile"
)

func main() {
	binary := flag.String("binary", "", "built release executable")
	platform := flag.String("os", "", "release operating system")
	architecture := flag.String("arch", "", "release architecture label")
	flag.Parse()
	if err := run(*binary, *platform, *architecture); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(binary, platform, architecture string) error {
	manifest, err := compatibility.Describe(context.Background(), binary, platform, architecture)
	if err != nil {
		return err
	}
	if err := manifest.VerifyPlatform(binary); err != nil {
		return err
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	path := binary + compatibility.Suffix
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("metadata destination is not a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return atomicfile.WriteFile(path, data, 0600)
}
