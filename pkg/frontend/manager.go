// Package frontend manages separately deployed, versioned UI bundles.
// The embedded UI remains the last-resort recovery image.
package frontend

import (
 "archive/tar"
 "compress/gzip"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "io/fs"
 "net/http"
 "net/url"
 "os"
 "path"
 "path/filepath"
 "regexp"
 "runtime"
 "runtime/debug"
 "strconv"
 "strings"
 "sync"
 "time"
)

const (
 FeedURL = "https://yuhaiin.github.io/ui-update.json"
 maxManifest = 32 << 10
 maxArchive = 32 << 20
 maxExpanded = 96 << 20
 maxEntries = 4096
)

var validVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)

type Build struct {
 Version string `json:"version"`
 BuildNumber int64 `json:"buildNumber"`
 APIContract int `json:"apiContract"`
 RequiredCapabilities []string `json:"requiredCapabilities,omitempty"`
 OptionalCapabilities []string `json:"optionalCapabilities,omitempty"`
 MinAndroidBridge int `json:"minAndroidBridge,omitempty"`
}

type Release struct {
 Build
 URL string `json:"url"`
 SHA256 string `json:"sha256"`
 Size int64 `json:"size"`
}

type Status struct {
 Source string `json:"source"`
 Active Build `json:"active"`
 Embedded Build `json:"embedded"`
 Installed *Build `json:"installed,omitempty"`
 Previous *Build `json:"previous,omitempty"`
 Capabilities []string `json:"capabilities"`
 Reason string `json:"reason,omitempty"`
}

type CheckResult struct {
 Status Status `json:"status"`
 Release Release `json:"release"`
 Available bool `json:"available"`
 Compatible bool `json:"compatible"`
 Reason string `json:"reason,omitempty"`
}

type ApplyRequest struct {
 Version string `json:"version"`
 SHA256 string `json:"sha256"`
}

type state struct {
 Current string `json:"current"`
 Previous string `json:"previous,omitempty"`
}

// Manager has no dependency on the Android UI. Gomobile uses the same local
// HTTP asset handler as desktop and never executes an unpacked native binary.
type Manager struct {
 mu sync.RWMutex
 embedded fs.FS
 embeddedBuild Build
 root string
 external string
 stored state
 client *http.Client
 feed string
 capabilities []string
}

func defaultCapabilities() []string {
 return []string{"rpc.v2", "management.v1", "inbounds.manage.v1", "nodes.manage.v1", "ssh.wrap.v1", "ssh.wrap.timezone.v1"}
}

func New(configPath string, embedded fs.FS) *Manager {
 m := &Manager{
  embedded: embedded,
  root: filepath.Join(configPath, "frontend-ui"),
  external: os.Getenv("EXTERNAL_WEB"),
  capabilities: defaultCapabilities(),
  feed: FeedURL,
  client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
   if len(via) >= 3 || req.URL.Scheme != "https" || req.URL.Hostname() != "yuhaiin.github.io" { return errors.New("frontend redirect outside the official origin") }
   return nil
  }},
 }
 m.embeddedBuild = embeddedMetadata(embedded)
 if data, err := os.ReadFile(filepath.Join(m.root, "state.json")); err == nil {
  var s state
  if json.Unmarshal(data, &s) == nil && validState(s) { m.stored = s }
 }
 return m
}

func embeddedMetadata(f fs.FS) Build {
 data, err := fs.ReadFile(f, "ui-build.json")
 if err == nil {
  var b Build
  if json.Unmarshal(data, &b) == nil && validBuild(b) { return b }
 }
 // Older embedded web modules do not contain ui-build.json. Their Go
 // pseudo-version still supplies a conservative timestamp for comparison.
 b := Build{Version: "embedded-legacy", APIContract: 1}
 if info, ok := debug.ReadBuildInfo(); ok {
  for _, d := range info.Deps {
   if d.Path != "github.com/yuhaiin/yuhaiin.github.io" { continue }
   v := d.Version
   if d.Replace != nil { v = d.Replace.Version }
   parts := strings.Split(v, "-")
   if len(parts) >= 3 && len(parts[len(parts)-2]) == 14 {
    if t, err := time.Parse("20060102150405", parts[len(parts)-2]); err == nil {
     b.BuildNumber = t.Unix()
     b.Version = v
    }
   }
   break
  }
 }
 return b
}

func validBuild(b Build) bool {
 return validVersion.MatchString(b.Version) && b.BuildNumber > 0 && b.APIContract > 0 && b.APIContract <= 100 && b.MinAndroidBridge >= 0
}

func validState(s state) bool {
 return (s.Current == "" || validVersion.MatchString(s.Current)) && (s.Previous == "" || validVersion.MatchString(s.Previous))
}

func (m *Manager) compatible(b Build) string {
 if !validBuild(b) { return "invalid_frontend_manifest" }
 if b.APIContract != 1 { return "unsupported_api_contract" }
 if runtime.GOOS == "android" && b.MinAndroidBridge > 0 { return "android_native_bridge_requires_app_update" }
 have := make(map[string]bool, len(m.capabilities))
 for _, c := range m.capabilities { have[c] = true }
 for _, need := range b.RequiredCapabilities {
  if !have[need] { return "missing_capability:" + need }
 }
 return ""
}

func (m *Manager) installed(version string) (Build, fs.FS, bool) {
 if !validVersion.MatchString(version) { return Build{}, nil, false }
 dir := filepath.Join(m.root, "versions", version)
 info, err := os.Lstat(dir)
 if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return Build{}, nil, false }
 disk := os.DirFS(dir)
 data, err := fs.ReadFile(disk, "ui-build.json")
 if err != nil || len(data) > maxManifest { return Build{}, nil, false }
 var b Build
 if json.Unmarshal(data, &b) != nil || !validBuild(b) || b.Version != version { return Build{}, nil, false }
 if _, err := fs.Stat(disk, "index.html"); err != nil { return Build{}, nil, false }
 return b, disk, true
}

// selection is calculated on every request/status so that an upgraded binary
// always outranks an older downloaded bundle even after process restart.
func (m *Manager) selection() (Build, fs.FS, string, string) {
 if m.external != "" { return m.embeddedBuild, os.DirFS(m.external), "external", "" }
 if b, disk, ok := m.installed(m.stored.Current); ok {
  if reason := m.compatible(b); reason == "" && b.BuildNumber > m.embeddedBuild.BuildNumber {
   return b, disk, "downloaded", ""
  }
 }
 if b, disk, ok := m.installed(m.stored.Previous); ok {
  if m.compatible(b) == "" && b.BuildNumber > m.embeddedBuild.BuildNumber {
   return b, disk, "previous", "current_frontend_is_unavailable"
  }
 }
 return m.embeddedBuild, m.embedded, "embedded", ""
}

func (m *Manager) statusLocked() Status {
 active, _, source, reason := m.selection()
 s := Status{Source: source, Active: active, Embedded: m.embeddedBuild, Capabilities: append([]string(nil), m.capabilities...), Reason: reason}
 if b, _, ok := m.installed(m.stored.Current); ok { s.Installed = &b }
 if b, _, ok := m.installed(m.stored.Previous); ok { s.Previous = &b }
 if source == "embedded" && s.Installed != nil && s.Installed.BuildNumber <= m.embeddedBuild.BuildNumber {
  s.Reason = "embedded_frontend_newer_or_equal"
 }
 return s
}

func (m *Manager) Status(context.Context) (Status, error) {
 m.mu.RLock()
 defer m.mu.RUnlock()
 return m.statusLocked(), nil
}

// Open implements fs.FS. Old immutable assets remain available while an
// already-open browser tab completes lazy imports after an OTA switch.
func (m *Manager) Open(name string) (fs.File, error) {
 if !fs.ValidPath(name) { return nil, fs.ErrInvalid }
 m.mu.RLock()
 defer m.mu.RUnlock()
 _, active, _, _ := m.selection()
 if f, err := active.Open(name); err == nil { return f, nil }
 if !strings.HasPrefix(name, "assets/") { return nil, fs.ErrNotExist }
 if m.external != "" { return nil, fs.ErrNotExist }
 for _, id := range []string{m.stored.Current, m.stored.Previous} {
  if _, disk, ok := m.installed(id); ok {
   if f, err := disk.Open(name); err == nil { return f, nil }
  }
 }
 return m.embedded.Open(name)
}

func (m *Manager) readFeed(ctx context.Context) (Release, error) {
 var release Release
 req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.feed, nil)
 if err != nil { return release, err }
 response, err := m.client.Do(req)
 if err != nil { return release, err }
 defer response.Body.Close()
 if response.StatusCode != http.StatusOK { return release, fmt.Errorf("frontend feed returned HTTP %d", response.StatusCode) }
 data, err := io.ReadAll(io.LimitReader(response.Body, maxManifest + 1))
 if err != nil || len(data) > maxManifest { return release, errors.New("frontend feed is too large") }
 if err := json.Unmarshal(data, &release); err != nil { return release, err }
 if !validBuild(release.Build) || release.Size <= 0 || release.Size > maxArchive || len(release.SHA256) != 64 {
  return release, errors.New("invalid frontend release metadata")
 }
 if _, err := hex.DecodeString(release.SHA256); err != nil { return release, err }
 u, err := url.Parse(release.URL)
 if err != nil || u.Scheme != "https" || u.Host != "yuhaiin.github.io" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/frontend.tar.gz" {
  return release, errors.New("frontend bundle URL must be the official HTTPS release")
 }
 return release, nil
}

func (m *Manager) Check(ctx context.Context) (CheckResult, error) {
 release, err := m.readFeed(ctx)
 if err != nil { return CheckResult{}, err }
 m.mu.RLock()
 defer m.mu.RUnlock()
 status := m.statusLocked()
 reason := m.compatible(release.Build)
 if m.external != "" { reason = "external_frontend_override" }
 available := release.BuildNumber > status.Active.BuildNumber
 if !available && reason == "" { reason = "current_frontend_is_newer_or_equal" }
 return CheckResult{Status: status, Release: release, Compatible: reason == "", Available: available && reason == "", Reason: reason}, nil
}

func (m *Manager) Apply(ctx context.Context, request ApplyRequest) (Status, error) {
 m.mu.Lock()
 defer m.mu.Unlock()
 if m.external != "" { return Status{}, errors.New("EXTERNAL_WEB disables managed frontend updates") }
 release, err := m.readFeed(ctx)
 if err != nil { return Status{}, err }
 if request.Version != release.Version || !strings.EqualFold(request.SHA256, release.SHA256) {
  return Status{}, errors.New("frontend release changed since check; check again")
 }
 if reason := m.compatible(release.Build); reason != "" { return Status{}, fmt.Errorf("incompatible frontend: %s", reason) }
 active, _, _, _ := m.selection()
 if release.BuildNumber <= active.BuildNumber { return Status{}, errors.New("frontend release is not newer than the selected frontend") }
 if err := os.MkdirAll(filepath.Join(m.root, "versions"), 0700); err != nil { return Status{}, err }
 tmp, err := os.MkdirTemp(filepath.Join(m.root, "versions"), ".incoming-")
 if err != nil { return Status{}, err }
 defer os.RemoveAll(tmp)
 if err := m.download(ctx, release, tmp); err != nil { return Status{}, err }
 dest := filepath.Join(m.root, "versions", release.Version)
 if _, err := os.Lstat(dest); err == nil { return Status{}, errors.New("release version already exists") } else if !errors.Is(err, os.ErrNotExist) { return Status{}, err }
 if err := os.Rename(tmp, dest); err != nil { return Status{}, err }
 next := state{Current: release.Version, Previous: m.stored.Current}
 if err := m.writeState(next); err != nil { return Status{}, err }
 m.stored = next
 return m.statusLocked(), nil
}

func (m *Manager) Rollback(context.Context) (Status, error) {
 m.mu.Lock()
 defer m.mu.Unlock()
 if m.external != "" { return Status{}, errors.New("external frontend override is active") }
 if m.stored.Current == "" { return m.statusLocked(), nil }
 next := state{Current: m.stored.Previous}
 if err := m.writeState(next); err != nil { return Status{}, err }
 m.stored = next
 return m.statusLocked(), nil
}

// Reset forces the trusted embedded UI, even when both saved OTA builds fail.
func (m *Manager) Reset(context.Context) (Status, error) {
 m.mu.Lock()
 defer m.mu.Unlock()
 if m.external != "" { return Status{}, errors.New("EXTERNAL_WEB override is active") }
 if err := os.MkdirAll(m.root, 0700); err != nil { return Status{}, err }
 if err := m.writeState(state{}); err != nil { return Status{}, err }
 m.stored = state{}
 return m.statusLocked(), nil
}

func (m *Manager) writeState(s state) error {
 data, err := json.Marshal(s)
 if err != nil { return err }
 temp, err := os.CreateTemp(m.root, ".state-")
 if err != nil { return err }
 defer os.Remove(temp.Name())
 defer temp.Close()
 if err := temp.Chmod(0600); err != nil { return err }
 if _, err := temp.Write(data); err != nil { return err }
 if err := temp.Sync(); err != nil { return err }
 if err := temp.Close(); err != nil { return err }
 return os.Rename(temp.Name(), filepath.Join(m.root, "state.json"))
}

func (m *Manager) download(ctx context.Context, release Release, destination string) error {
 req, err := http.NewRequestWithContext(ctx, http.MethodGet, release.URL, nil)
 if err != nil { return err }
 resp, err := m.client.Do(req)
 if err != nil { return err }
 defer resp.Body.Close()
 if resp.StatusCode != http.StatusOK { return fmt.Errorf("frontend bundle returned HTTP %d", resp.StatusCode) }
 archive, err := os.CreateTemp(m.root, ".download-")
 if err != nil { return err }
 defer os.Remove(archive.Name())
 defer archive.Close()
 n, err := io.Copy(archive, io.LimitReader(resp.Body, maxArchive+1))
 if err != nil || n != release.Size { return errors.New("frontend bundle size mismatch") }
 if _, err := archive.Seek(0, io.SeekStart); err != nil { return err }
 hash := sha256.New()
 if _, err := io.Copy(hash, archive); err != nil { return err }
 if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), release.SHA256) { return errors.New("frontend bundle checksum mismatch") }
 if _, err := archive.Seek(0, io.SeekStart); err != nil { return err }
 zipped, err := gzip.NewReader(archive)
 if err != nil { return err }
 defer zipped.Close()
 tarReader := tar.NewReader(zipped)
 var count, expanded int64
 for {
  header, err := tarReader.Next()
  if errors.Is(err, io.EOF) { break }
  if err != nil { return err }
  name := strings.TrimPrefix(header.Name, "./")
  if header.Typeflag == tar.TypeDir { name = strings.TrimSuffix(name, "/") }
  if name == "" || name == "." { continue }
  if !fs.ValidPath(name) || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "api/") {
   return fmt.Errorf("unsafe frontend archive path: %q", name)
  }
  count++
  if count > maxEntries { return errors.New("too many frontend bundle entries") }
  target := filepath.Join(destination, filepath.FromSlash(name))
  switch header.Typeflag {
  case tar.TypeDir:
   if err := os.MkdirAll(target, 0700); err != nil { return err }
  case tar.TypeReg, tar.TypeRegA:
   if header.Size < 0 || header.Size > maxExpanded-expanded { return errors.New("frontend bundle exceeds expanded size limit") }
   expanded += header.Size
   if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil { return err }
   file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
   if err != nil { return err }
   n, copyErr := io.Copy(file, io.LimitReader(tarReader, header.Size))
   closeErr := file.Close()
   if copyErr != nil { return copyErr }
   if closeErr != nil { return closeErr }
   if n != header.Size { return errors.New("truncated frontend archive member") }
  default:
   return errors.New("frontend bundle contains an unsupported entry type")
  }
 }
 disk := os.DirFS(destination)
 raw, err := fs.ReadFile(disk, "ui-build.json")
 if err != nil || len(raw) > maxManifest { return errors.New("missing frontend build metadata") }
 var embedded Build
 if json.Unmarshal(raw, &embedded) != nil || embedded.Version != release.Version || embedded.BuildNumber != release.BuildNumber || embedded.APIContract != release.APIContract || embedded.MinAndroidBridge != release.MinAndroidBridge || strings.Join(embedded.RequiredCapabilities, "\x00") != strings.Join(release.RequiredCapabilities, "\x00") {
  return errors.New("frontend metadata does not match signed-off release manifest")
 }
 index, err := fs.ReadFile(disk, "index.html")
 if err != nil || len(index) == 0 { return errors.New("frontend bundle has no entry page") }
 // Reject a misconfigured archive which could claim compatibility before
 // quietly dropping a required capability from the installed copy.
 return nil
}

// BundleTime exposes a deterministic date for legacy Go pseudo-version tests.
func BundleTime(unix int64) string { return strconv.FormatInt(unix, 10) }

// PathIsAsset keeps frontend pages from catching unexpected API routes.
func PathIsAsset(name string) bool { return !strings.HasPrefix(path.Clean("/"+name), "/api/") }
