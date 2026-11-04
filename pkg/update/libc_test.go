package update

import (
	"testing"
	"time"

	contractupdate "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
)

func TestSelectReleaseLinuxABI(t *testing.T) {
	for _, channel := range []string{contractupdate.ChannelStable, contractupdate.ChannelBeta, contractupdate.ChannelMain} {
		for _, arch := range []string{"amd64", "amd64v3", "amd64v4", "arm64", "mipsle"} {
			for _, abi := range []string{"glibc", "static", ""} {
				t.Run(channel+"/"+arch+"/"+abi, func(t *testing.T) {
					base := "yuhaiin-linux-" + arch
					candidate := release{Tag: "v2.0.0", Assets: []releaseAsset{{Name: base, URL: "static"}, {Name: base + "-glibc", URL: "glibc"}, {Name: base + compatibility.Suffix, URL: "static-metadata"}, {Name: base + "-glibc" + compatibility.Suffix, URL: "glibc-metadata"}, {Name: "checksums.txt", URL: "checksums"}}}
					if channel == contractupdate.ChannelBeta {
						candidate.Tag = "v2.0.0-beta.1"
						candidate.Prerelease = true
					}
					if channel == contractupdate.ChannelMain {
						candidate.Tag = "main"
						candidate.Name = "main-new"
						candidate.Prerelease = true
					}
					got, ok := selectReleaseChannel([]release{candidate}, "v1.0.0", "old", time.Time{}, channel, "linux", arch, abi)
					want := "static"
					if abi == "glibc" && arch != "mipsle" {
						want = "glibc"
					}
					if !ok || got.Asset.URL != want || got.Asset.CompatibilityURL != want+"-metadata" {
						t.Fatalf("selected %+v, want %s", got.Asset, want)
					}
					// Previous releases contain only the portable asset. A new updater must
					// still be able to select these without requiring a new manifest format.
					candidate.Assets = append(candidate.Assets[:1], candidate.Assets[2:]...)
					got, ok = selectReleaseChannel([]release{candidate}, "v1.0.0", "old", time.Time{}, channel, "linux", arch, abi)
					if !ok || got.Asset.URL != "static" {
						t.Fatalf("portable fallback: %+v, %v", got.Asset, ok)
					}
				})
			}
		}
	}
}

func TestMuslRejectsGlibcManifestBeforeSchemaInspection(t *testing.T) {
	svc := NewService(Options{TargetOS: "linux", TargetArch: "amd64", TargetABI: "static"})
	status, err := svc.inspectCompatibility(t.Context(), compatibility.Manifest{Platform: "linux", Architecture: "amd64", Asset: "yuhaiin-linux-amd64-glibc"})
	if err != nil || status.Reason != "target_libc_mismatch" {
		t.Fatalf("admission: %+v, %v", status, err)
	}
}
