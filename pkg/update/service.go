package update

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractupdate "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	"golang.org/x/mod/semver"
)

const defaultReleasesURL = "https://api.github.com/repos/yuhaiin/yuhaiin/releases"
const updateHTTPTimeout = 30 * time.Minute

type Asset struct {
	Name             string
	URL              string
	ChecksumURL      string
	CompatibilityURL string
	SHA256           string
	Size             int64
}

type Installer interface {
	Supported() (bool, string)
	Start(context.Context, string) error
}

type stagingDirProvider interface{ StagingDir() string }

type Options struct {
	HTTPClient       *http.Client
	ReleasesURL      string
	Installer        Installer
	CurrentVersion   string
	TargetOS         string
	TargetArch       string
	CurrentTimestamp time.Time
	CurrentCommit    string
}

type Service struct {
	client           *http.Client
	releasesURL      string
	installer        Installer
	current          string
	targetOS         string
	targetArch       string
	currentTimestamp time.Time
	currentCommit    string
	mu               sync.RWMutex
	status           contractupdate.Status
}

func NewService(opt Options) *Service {
	client := opt.HTTPClient
	if client == nil {
		client = proxyHTTPClient()
	}
	releasesURL := opt.ReleasesURL
	if releasesURL == "" {
		releasesURL = defaultReleasesURL
	}
	current := opt.CurrentVersion
	if current == "" {
		current = version.Version
	}
	targetOS := opt.TargetOS
	if targetOS == "" {
		targetOS = runtime.GOOS
	}
	targetArch := opt.TargetArch
	if targetArch == "" {
		targetArch = version.ReleaseArch
		if targetArch == "" {
			targetArch = runtime.GOARCH
		}
	}
	currentTimestamp := opt.CurrentTimestamp
	if currentTimestamp.IsZero() && version.ReleaseTimestamp != "" {
		currentTimestamp, _ = time.Parse(time.RFC3339, version.ReleaseTimestamp)
	}
	currentCommit := opt.CurrentCommit
	if currentCommit == "" {
		currentCommit = version.GitCommit
	}
	return &Service{client: client, releasesURL: releasesURL, installer: opt.Installer, current: current, targetOS: targetOS, targetArch: targetArch, currentTimestamp: currentTimestamp, currentCommit: currentCommit}
}

// proxyHTTPClient routes GitHub API, release assets, and checksum downloads
// through the same dynamic proxy chain used by rule-list downloads.
func proxyHTTPClient() *http.Client {
	return &http.Client{
		Timeout: updateHTTPTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(network, addr)
				if err != nil {
					return nil, fmt.Errorf("parse update address failed: %w", err)
				}
				return configuration.ProxyChain.Conn(ctx, ad)
			},
		},
	}
}

// NewProxyHTTPClient returns an HTTP client that routes requests through the
// configured proxy chain. It is also used by the Android binding for APK
// update downloads.
func NewProxyHTTPClient() *http.Client {
	return proxyHTTPClient()
}

func (s *Service) Check(ctx context.Context, channel string) (contractupdate.CheckResult, error) {
	channel = normalizeChannel(channel)
	result := contractupdate.CheckResult{Supported: s.installer != nil, CurrentVersion: s.current, Channel: channel}
	if s.installer == nil {
		result.Reason = "automatic updates are not supported on this platform"
	} else if supported, reason := s.installer.Supported(); !supported {
		result.Reason = reason
		result.Supported = false
	}
	if !result.Supported {
		return result, nil
	}
	releases, err := s.releases(ctx)
	if err != nil {
		return result, err
	}
	selected, ok := selectReleaseChannel(releases, s.current, s.currentCommit, s.currentTimestamp, channel, s.targetOS, s.targetArch)
	if !ok {
		log.Info("software update no newer release", "channel", channel, "current", s.current, "commit", s.currentCommit, "os", s.targetOS, "arch", s.targetArch, "releases", len(releases))
		result.Reason = "no newer release found for this platform"
		return result, nil
	}
	result.TargetVersion = selected.Version
	result.TargetTag = selected.Tag
	result.Prerelease = selected.Prerelease
	result.ReleaseURL = selected.HTMLURL
	result.ReleaseNotes = selected.Notes
	result.PublishedAt = selected.PublishedAt
	result.AssetName = selected.Asset.Name
	checksum, err := s.assetChecksum(ctx, selected.Asset)
	if err != nil {
		return result, err
	}
	result.AssetSHA256 = checksum
	result.UpdateAvailable = true
	manifest, manifestErr := s.releaseCompatibility(ctx, selected.Asset)
	if manifestErr != nil {
		result.Compatibility = &contractupdate.CompatibilityStatus{State: "unknown", Reason: "release_manifest_unverified"}
		result.Reason = manifestErr.Error()
		return result, nil
	}
	status, inspectErr := s.inspectCompatibility(ctx, manifest)
	result.Compatibility = &status
	if inspectErr != nil {
		result.Reason = "database compatibility inspection failed"
	}
	return result, nil
}

func (s *Service) Apply(ctx context.Context, request contractupdate.ApplyRequest) error {
	if s.installer == nil {
		return errors.New("automatic updates are not supported on this platform")
	}
	if request.TargetTag == "" {
		return errors.New("target tag is required")
	}
	if supported, reason := s.installer.Supported(); !supported {
		return errors.New(reason)
	}

	s.mu.Lock()
	if s.status.Running {
		s.mu.Unlock()
		return errors.New("an update is already running")
	}
	s.status = contractupdate.Status{Running: true, Stage: "preparing"}
	s.mu.Unlock()
	log.Info("start software update", "channel", request.Channel, "targetTag", request.TargetTag)
	fail := func(err error) error {
		s.finishUpdate(err)
		return err
	}

	log.Info("software update preparing release metadata", "url", s.releasesURL)
	releases, err := s.releases(ctx)
	if err != nil {
		return fail(err)
	}
	log.Info("software update release metadata received", "count", len(releases))
	channel := request.Channel
	if channel == "" {
		channel = contractupdate.ChannelStable
		if request.IncludePrerelease {
			channel = contractupdate.ChannelBeta
		}
	}
	selected, ok := selectReleaseChannel(releases, s.current, s.currentCommit, s.currentTimestamp, normalizeChannel(channel), s.targetOS, s.targetArch)
	if !ok || selected.Tag != request.TargetTag {
		return fail(errors.New("requested release is no longer available"))
	}
	manifest, err := s.releaseCompatibility(ctx, selected.Asset)
	if err != nil {
		return fail(err)
	}
	if request.ExpectedSHA256 != "" && !strings.EqualFold(request.ExpectedSHA256, manifest.SHA256) {
		return fail(errors.New("release changed after review; check for updates again"))
	}
	selected.Asset.SHA256 = manifest.SHA256
	compatibilityStatus, err := s.inspectCompatibility(ctx, manifest)
	if err != nil {
		return fail(err)
	}
	if compatibilityStatus.State != "compatible" {
		return fail(errors.New("automatic installation requires a compatible schema; migrations require a coordinated recovery point"))
	}
	log.Info("software update release selected", "version", selected.Version, "tag", selected.Tag, "asset", selected.Asset.Name, "size", selected.Asset.Size)

	s.mu.Lock()
	s.status.Stage = "downloading"
	s.status.Progress = 0
	s.status.BytesDownloaded = 0
	s.status.TotalBytes = selected.Asset.Size
	s.mu.Unlock()

	go func() {
		log.Info("software update download started", "asset", selected.Asset.Name)
		err := s.downloadAndInstall(context.Background(), selected.Asset)
		s.finishUpdate(err)
	}()
	return nil
}

func (s *Service) History(ctx context.Context) (contractupdate.HistoryResult, error) {
	entries, err := ListHistory(configuration.DataDir.Load())
	for i := range entries {
		status := contractupdate.CompatibilityStatus{State: "unknown", Reason: "history_manifest_unavailable"}
		manifest, readErr := historyCompatibility(configuration.DataDir.Load(), entries[i].ID)
		if readErr == nil {
			status, readErr = s.inspectCompatibility(ctx, manifest)
			if readErr != nil {
				status.State = "unknown"
			}
		}
		entries[i].Compatibility = &status
	}
	return contractupdate.HistoryResult{Items: entries}, err
}

// Rollback uses the same verified installer and restart path as a normal update.
func (s *Service) Rollback(ctx context.Context, request contractupdate.RollbackRequest) error {
	if s.installer == nil {
		return errors.New("automatic updates are not supported on this platform")
	}
	if ok, reason := s.installer.Supported(); !ok {
		return errors.New(reason)
	}
	if !validHistoryID(request.ID) {
		return errors.New("invalid history ID")
	}
	history, err := ListHistory(configuration.DataDir.Load())
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(history, func(item contractupdate.HistoryEntry) bool { return item.ID == request.ID }) {
		return errors.New("history version not found")
	}
	manifest, err := historyCompatibility(configuration.DataDir.Load(), request.ID)
	if err != nil {
		return errors.New("old binary has no verified schema descriptor; use offline recovery with matching databases")
	}
	status, err := s.inspectCompatibility(ctx, manifest)
	if err != nil {
		return err
	}
	if status.State != "compatible" {
		return errors.New("binary rollback is incompatible with the current databases; restore a matching database recovery point offline")
	}
	provider, ok := s.installer.(stagingDirProvider)
	if !ok {
		return errors.New("rollback staging is unsupported")
	}
	s.mu.Lock()
	if s.status.Running {
		s.mu.Unlock()
		return errors.New("an update is already running")
	}
	s.status = contractupdate.Status{Running: true, Stage: "preparing"}
	s.mu.Unlock()
	go func() {
		staged, err := StageHistory(configuration.DataDir.Load(), request.ID, provider.StagingDir())
		if err == nil {
			s.updateProgress("installing", 1, 1)
			err = s.installer.Start(context.Background(), staged)
			if err != nil {
				_ = os.Remove(staged + compatibility.Suffix)
				_ = os.Remove(staged)
			}
		}
		s.finishUpdate(err)
	}()
	return nil
}

func (s *Service) Status(context.Context) contractupdate.Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *Service) updateProgress(stage string, downloaded, total int64) {
	progress := 0
	if total > 0 {
		progress = min(int(downloaded*100/total), 100)
	}
	s.mu.Lock()
	s.status.Stage = stage
	s.status.Progress = progress
	s.status.BytesDownloaded = downloaded
	s.status.TotalBytes = total
	s.mu.Unlock()
}

func (s *Service) finishUpdate(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Running = false
	s.status.Error = errorString(err)
	if err != nil {
		s.status.Stage = "error"
		log.Error("software update failed", "err", err)
		return
	}
	s.status.Stage = "completed"
	s.status.Progress = 100
	log.Info("software update install helper started")
}

type release struct {
	Tag         string         `json:"tag_name"`
	Name        string         `json:"name"`
	Prerelease  bool           `json:"prerelease"`
	Draft       bool           `json:"draft"`
	HTMLURL     string         `json:"html_url"`
	Notes       string         `json:"body"`
	PublishedAt time.Time      `json:"published_at"`
	Assets      []releaseAsset `json:"assets"`
	Version     string
	Asset       Asset
}

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

func (s *Service) releases(ctx context.Context) ([]release, error) {
	var all []release
	for page := 1; ; page++ {
		u, err := url.Parse(s.releasesURL)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("per_page", "100")
		q.Set("page", fmt.Sprint(page))
		// The request still goes through the configured proxy chain, but the
		// unique query prevents an intermediary from serving an old release list.
		q.Set("update_cache_bust", strconv.FormatInt(time.Now().UnixNano(), 10))
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", version.AppName+"/"+version.Version)
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")
		resp, err := s.client.Do(req)
		if err != nil {
			return nil, err
		}
		var pageReleases []release
		decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&pageReleases)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, decodeErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("github releases request failed: %s", resp.Status)
		}
		all = append(all, pageReleases...)
		if len(pageReleases) < 100 {
			return all, nil
		}
	}
}

func selectRelease(releases []release, current string, includePrerelease bool, targetOS, targetArch string) (release, bool) {
	channel := contractupdate.ChannelStable
	if includePrerelease {
		channel = contractupdate.ChannelBeta
	}
	return selectReleaseChannel(releases, current, "", time.Time{}, channel, targetOS, targetArch)
}

func selectReleaseChannel(releases []release, current, currentCommit string, currentTimestamp time.Time, channel, targetOS, targetArch string) (release, bool) {
	channel = normalizeChannel(channel)
	currentVersion := normalizeVersion(current)
	trimmedCurrent := strings.TrimSpace(current)
	isCurrentMain := trimmedCurrent == "main"
	var candidates []release
	assetName := "yuhaiin-" + targetOS + "-" + targetArch
	if targetOS == "windows" {
		assetName += ".exe"
	}
	for _, item := range releases {
		mainVersion := mainReleaseVersion(item)
		if item.Draft || channel == contractupdate.ChannelMain && mainVersion == "" {
			continue
		}
		if channel == contractupdate.ChannelStable && (item.Prerelease || mainVersion != "") {
			continue
		}
		if channel == contractupdate.ChannelBeta && (!item.Prerelease || mainVersion != "") {
			continue
		}
		if channel == contractupdate.ChannelMain {
			item.Version = mainVersion
		} else {
			item.Version = normalizeVersion(item.Tag)
			if item.Version == "" || currentVersion == "" || compareVersion(item.Version, currentVersion) <= 0 {
				continue
			}
		}
		for _, a := range item.Assets {
			if a.Name == assetName {
				item.Asset = Asset{Name: a.Name, URL: a.URL, Size: a.Size}
				break
			}
		}
		if item.Asset.Name == "" {
			continue
		}
		for _, a := range item.Assets {
			if a.Name == assetName+compatibility.Suffix {
				item.Asset.CompatibilityURL = a.URL
			}
		}
		for _, a := range item.Assets {
			if a.Name == "checksums.txt" {
				item.Asset.ChecksumURL = a.URL
				break
			}
		}
		if item.Asset.ChecksumURL == "" {
			continue
		}
		candidates = append(candidates, item)
	}
	if len(candidates) == 0 {
		return release{}, false
	}
	if channel == contractupdate.ChannelMain {
		slices.SortFunc(candidates, func(a, b release) int {
			if a.PublishedAt.Equal(b.PublishedAt) {
				return cmp.Compare(b.Version, a.Version)
			}
			return b.PublishedAt.Compare(a.PublishedAt)
		})
		selected := candidates[0]
		if sameMainVersion(current, selected.Version, currentCommit) {
			return release{}, false
		}
		if isCurrentMain && currentCommit == "" && !currentTimestamp.IsZero() && !selected.PublishedAt.After(currentTimestamp) {
			return release{}, false
		}
		return selected, true
	} else {
		slices.SortFunc(candidates, func(a, b release) int { return compareVersion(b.Version, a.Version) })
	}
	return candidates[0], true
}

func sameMainVersion(current, release, commit string) bool {
	current = strings.TrimPrefix(strings.TrimSpace(current), "main-")
	release = strings.TrimPrefix(strings.TrimSpace(release), "main-")
	if current != "" && release != "" && (current == release || strings.HasPrefix(release, current) || strings.HasPrefix(current, release)) {
		return true
	}
	return commit != "" && release != "" && (strings.HasPrefix(release, commit) || strings.HasPrefix(commit, release))
}

func mainReleaseVersion(item release) string {
	if strings.HasPrefix(strings.TrimSpace(item.Name), "main-") {
		return strings.TrimSpace(item.Name)
	}
	if strings.HasPrefix(strings.TrimSpace(item.Tag), "main-") {
		return strings.TrimSpace(item.Tag)
	}
	return ""
}

func normalizeChannel(channel string) string {
	switch strings.ToLower(strings.TrimSpace(channel)) {
	case contractupdate.ChannelBeta:
		return contractupdate.ChannelBeta
	case contractupdate.ChannelMain:
		return contractupdate.ChannelMain
	default:
		return contractupdate.ChannelStable
	}
}

func (s *Service) downloadAndInstall(ctx context.Context, asset Asset) error {
	ctx, cancel := context.WithTimeout(ctx, updateHTTPTimeout)
	defer cancel()
	manifest, err := s.releaseCompatibility(ctx, asset)
	if err != nil {
		return err
	}
	if asset.SHA256 != "" && manifest.SHA256 != asset.SHA256 {
		return errors.New("release changed after admission; check for updates again")
	}
	if asset.ChecksumURL == "" {
		return errors.New("release checksum asset is missing")
	}
	tempDir := ""
	if provider, ok := s.installer.(stagingDirProvider); ok {
		tempDir = provider.StagingDir()
	}
	tmp, err := os.CreateTemp(tempDir, "yuhaiin-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	lastLoggedProgress := -10
	if err := download(ctx, s.client, asset.URL, tmp, func(downloaded, total int64) {
		if total <= 0 {
			total = asset.Size
		}
		if total > 0 {
			progress := int(downloaded * 100 / total)
			if progress >= lastLoggedProgress+10 || progress >= 100 {
				log.Info("software update download progress", "progress", progress, "downloaded", downloaded, "total", total)
				lastLoggedProgress = progress
			}
		}
		s.updateProgress("downloading", downloaded, total)
	}); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	log.Info("software update download finished", "asset", asset.Name)
	s.updateProgress("verifying", asset.Size, asset.Size)
	log.Info("software update checksum verification started", "asset", asset.Name)
	checksum, err := downloadText(ctx, s.client, asset.ChecksumURL)
	if err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	want, err := parseChecksum(checksum, asset.Name)
	if err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	hash, err := fileSHA256(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if !strings.EqualFold(hash, want) {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("checksum mismatch: got %s want %s", hash, want)
	}
	info, err := os.Stat(tmpPath)
	if err != nil || info.Size() != manifest.Size || hash != manifest.SHA256 {
		_ = os.Remove(tmpPath)
		return errors.New("downloaded binary differs from the verified schema manifest")
	}
	status, err := s.inspectCompatibility(ctx, manifest)
	if err != nil || status.State != "compatible" {
		_ = os.Remove(tmpPath)
		return errors.New("database compatibility changed before installation")
	}
	if err := writeStagedCompatibility(tmpPath, manifest); err != nil {
		_ = os.Remove(tmpPath)
		_ = os.Remove(tmpPath + compatibility.Suffix)
		return err
	}
	log.Info("software update checksum verification passed", "asset", asset.Name)
	s.updateProgress("installing", asset.Size, asset.Size)
	log.Info("software update installer starting", "asset", asset.Name)
	if err := s.installer.Start(ctx, tmpPath); err != nil {
		_ = os.Remove(tmpPath + compatibility.Suffix)
		_ = os.Remove(tmpPath)
		return err
	}
	// Start owns the staged file after successfully launching the platform helper.
	return nil
}

func (s *Service) assetChecksum(ctx context.Context, asset Asset) (string, error) {
	text, err := downloadText(ctx, s.client, asset.ChecksumURL)
	if err != nil {
		return "", err
	}
	return parseChecksum(text, asset.Name)
}

func download(ctx context.Context, client *http.Client, rawURL string, dst *os.File, progress func(downloaded, total int64)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download failed: %s", resp.Status)
	}
	if resp.ContentLength > compatibility.MaxBinaryBytes {
		return errors.New("update binary exceeds 512 MiB")
	}
	writer := progressWriter{writer: dst, total: resp.ContentLength, progress: progress}
	n, err := io.Copy(&writer, io.LimitReader(resp.Body, compatibility.MaxBinaryBytes+1))
	if n > compatibility.MaxBinaryBytes {
		return errors.New("update binary exceeds 512 MiB")
	}
	return err
}

type progressWriter struct {
	writer   io.Writer
	total    int64
	written  int64
	progress func(downloaded, total int64)
}

func (w *progressWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.written += int64(n)
	if w.progress != nil {
		w.progress(w.written, w.total)
	}
	return n, err
}

func downloadText(ctx context.Context, client *http.Client, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("checksum download failed: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if len(b) > 4<<20 {
		return "", errors.New("release checksum file exceeds 4 MiB")
	}
	return string(b), err
}

func parseChecksum(text, name string) (string, error) {
	var found string
	for line := range strings.SplitSeq(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || filepath.Base(fields[len(fields)-1]) != name {
			continue
		}
		if found != "" {
			return "", errors.New("release has ambiguous duplicate checksums")
		}
		if len(fields[0]) != sha256.Size*2 {
			return "", errors.New("invalid release checksum")
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			return "", errors.New("invalid release checksum")
		}
		found = strings.ToLower(fields[0])
	}
	if found == "" {
		return "", fmt.Errorf("checksum for %s is missing", name)
	}
	return found, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), err
}

func normalizeVersion(value string) string {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if value == "" || strings.ContainsAny(value, " \t\n") {
		return ""
	}
	value = "v" + value
	if !semver.IsValid(value) {
		return ""
	}
	return value
}

func compareVersion(a, b string) int {
	return semver.Compare(a, b)
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
