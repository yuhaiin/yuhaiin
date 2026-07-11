package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/version"
	contractupdate "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	"golang.org/x/mod/semver"
)

const defaultReleasesURL = "https://api.github.com/repos/yuhaiin/yuhaiin/releases"

type Asset struct {
	Name        string
	URL         string
	ChecksumURL string
	SHA256      string
	Size        int64
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
}

type Service struct {
	client           *http.Client
	releasesURL      string
	installer        Installer
	current          string
	targetOS         string
	targetArch       string
	currentTimestamp time.Time
	mu               sync.RWMutex
	status           contractupdate.Status
}

func NewService(opt Options) *Service {
	client := opt.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
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
	return &Service{client: client, releasesURL: releasesURL, installer: opt.Installer, current: current, targetOS: targetOS, targetArch: targetArch, currentTimestamp: currentTimestamp}
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
	selected, ok := selectReleaseChannel(releases, s.current, s.currentTimestamp, channel, s.targetOS, s.targetArch)
	if !ok {
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
	releases, err := s.releases(ctx)
	if err != nil {
		return err
	}
	channel := request.Channel
	if channel == "" {
		channel = contractupdate.ChannelStable
		if request.IncludePrerelease {
			channel = contractupdate.ChannelBeta
		}
	}
	selected, ok := selectReleaseChannel(releases, s.current, s.currentTimestamp, normalizeChannel(channel), s.targetOS, s.targetArch)
	if !ok || selected.Tag != request.TargetTag {
		return errors.New("requested release is no longer available")
	}

	s.mu.Lock()
	if s.status.Running {
		s.mu.Unlock()
		return errors.New("an update is already running")
	}
	s.status = contractupdate.Status{Running: true}
	s.mu.Unlock()

	go func() {
		err := s.downloadAndInstall(context.Background(), selected.Asset)
		s.mu.Lock()
		s.status = contractupdate.Status{Error: errorString(err)}
		s.mu.Unlock()
	}()
	return nil
}

func (s *Service) Status(context.Context) contractupdate.Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
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
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", version.AppName+"/"+version.Version)
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
	return selectReleaseChannel(releases, current, time.Time{}, channel, targetOS, targetArch)
}

func selectReleaseChannel(releases []release, current string, currentTimestamp time.Time, channel, targetOS, targetArch string) (release, bool) {
	channel = normalizeChannel(channel)
	currentVersion := normalizeVersion(current)
	isCurrentMain := strings.HasPrefix(strings.TrimSpace(current), "main-")
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
			if item.Version == current || isCurrentMain && !currentTimestamp.IsZero() && !item.PublishedAt.After(currentTimestamp) {
				continue
			}
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
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].PublishedAt.Equal(candidates[j].PublishedAt) {
				return candidates[i].Version > candidates[j].Version
			}
			return candidates[i].PublishedAt.After(candidates[j].PublishedAt)
		})
	} else {
		sort.Slice(candidates, func(i, j int) bool { return compareVersion(candidates[i].Version, candidates[j].Version) > 0 })
	}
	return candidates[0], true
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
	if err := download(ctx, s.client, asset.URL, tmp); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
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
	if err := s.installer.Start(ctx, tmpPath); err != nil {
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

func download(ctx context.Context, client *http.Client, rawURL string, dst *os.File) error {
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
	_, err = io.Copy(dst, io.LimitReader(resp.Body, 512<<20))
	return err
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
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return string(b), err
}

func parseChecksum(text, name string) (string, error) {
	for line := range strings.SplitSeq(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && filepath.Base(fields[len(fields)-1]) == name && len(fields[0]) == sha256.Size*2 {
			if _, err := hex.DecodeString(fields[0]); err == nil {
				return fields[0], nil
			}
		}
	}
	return "", fmt.Errorf("checksum for %s is missing", name)
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
