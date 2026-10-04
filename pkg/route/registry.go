package route

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const (
	registrySchemaVersion = 1
	maxRegistryBodySize   = 8 << 20
	maxRegistryFiles      = 20000
)

type RegistryBook interface {
	ListRegistries(context.Context) (contractroute.RegistryList, error)
}

type registryCacheEntry struct {
	sourceURL string
	expiresAt time.Time
	catalog   contractroute.RegistryCatalog
}

type RegistryCatalogService struct {
	registries RegistryBook
	client     *http.Client
	ttl        time.Duration

	mu    sync.Mutex
	cache map[string]registryCacheEntry
}

func NewRegistryCatalogService(registries RegistryBook) *RegistryCatalogService {
	return newRegistryCatalogService(registries, registryHTTPClient(), 30*time.Minute)
}

func newRegistryCatalogService(registries RegistryBook, client *http.Client, ttl time.Duration) *RegistryCatalogService {
	return &RegistryCatalogService{
		registries: registries,
		client:     client,
		ttl:        ttl,
		cache:      make(map[string]registryCacheEntry),
	}
}

func (s *RegistryCatalogService) Catalogs(ctx context.Context, refresh bool) (contractroute.RegistryCatalogList, error) {
	if s == nil || s.registries == nil {
		return contractroute.RegistryCatalogList{}, errors.New("route registry catalog service is unavailable")
	}

	registries, err := s.registries.ListRegistries(ctx)
	if err != nil {
		return contractroute.RegistryCatalogList{}, err
	}

	enabled := make([]contractroute.Registry, 0, len(registries.Items))
	for _, registry := range registries.Items {
		if registry.Enabled {
			enabled = append(enabled, registry)
		}
	}

	out := contractroute.RegistryCatalogList{Items: make([]contractroute.RegistryCatalog, len(enabled))}
	var wg sync.WaitGroup
	for i, registry := range enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			catalog, err := s.catalog(ctx, registry, refresh)
			if err != nil {
				catalog = contractroute.RegistryCatalog{Registry: registry, Error: err.Error()}
			}
			out.Items[i] = catalog
		}()
	}
	wg.Wait()
	return out, nil
}

func (s *RegistryCatalogService) catalog(ctx context.Context, registry contractroute.Registry, refresh bool) (contractroute.RegistryCatalog, error) {
	if !refresh {
		s.mu.Lock()
		cached, ok := s.cache[registry.ID]
		s.mu.Unlock()
		if ok && cached.sourceURL == registry.URL && time.Now().Before(cached.expiresAt) {
			return cached.catalog, nil
		}
	}

	catalog, err := s.fetch(ctx, registry)
	if err != nil {
		return contractroute.RegistryCatalog{}, err
	}

	s.mu.Lock()
	s.cache[registry.ID] = registryCacheEntry{
		sourceURL: registry.URL,
		expiresAt: time.Now().Add(s.ttl),
		catalog:   catalog,
	}
	s.mu.Unlock()

	return catalog, nil
}

func (s *RegistryCatalogService) fetch(ctx context.Context, registry contractroute.Registry) (contractroute.RegistryCatalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, registry.URL, nil)
	if err != nil {
		return contractroute.RegistryCatalog{}, fmt.Errorf("create registry request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "yuhaiin-registry/1")

	resp, err := s.client.Do(req)
	if err != nil {
		return contractroute.RegistryCatalog{}, fmt.Errorf("fetch registry %q: %w", registry.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return contractroute.RegistryCatalog{}, fmt.Errorf("fetch registry %q: HTTP %d: %s", registry.Name, resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryBodySize+1))
	if err != nil {
		return contractroute.RegistryCatalog{}, fmt.Errorf("read registry %q: %w", registry.Name, err)
	}
	if len(data) > maxRegistryBodySize {
		return contractroute.RegistryCatalog{}, fmt.Errorf("registry %q exceeds %d bytes", registry.Name, maxRegistryBodySize)
	}

	var manifest contractroute.RegistryManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return contractroute.RegistryCatalog{}, fmt.Errorf("decode registry %q: %w", registry.Name, err)
	}
	if manifest.SchemaVersion != registrySchemaVersion {
		return contractroute.RegistryCatalog{}, fmt.Errorf("registry %q schema version %d is unsupported", registry.Name, manifest.SchemaVersion)
	}
	if len(manifest.Files) > maxRegistryFiles {
		return contractroute.RegistryCatalog{}, fmt.Errorf("registry %q has too many files: %d", registry.Name, len(manifest.Files))
	}

	seen := make(map[string]struct{}, len(manifest.Files))
	files := make([]contractroute.RegistryFile, 0, len(manifest.Files))
	for _, file := range manifest.Files {
		file.ID = strings.TrimSpace(file.ID)
		file.Name = strings.TrimSpace(file.Name)
		file.Path = strings.TrimSpace(file.Path)
		file.URL = strings.TrimSpace(file.URL)
		if file.ID == "" {
			return contractroute.RegistryCatalog{}, fmt.Errorf("registry %q contains a file with an empty id", registry.Name)
		}
		if _, ok := seen[file.ID]; ok {
			return contractroute.RegistryCatalog{}, fmt.Errorf("registry %q contains duplicate file id %q", registry.Name, file.ID)
		}
		seen[file.ID] = struct{}{}

		if file.URL == "" && manifest.BaseURL != "" && file.Path != "" {
			resolved, err := resolveRegistryURL(manifest.BaseURL, file.Path)
			if err != nil {
				return contractroute.RegistryCatalog{}, fmt.Errorf("resolve registry file %q: %w", file.ID, err)
			}
			file.URL = resolved
		}
		if file.Selectable || file.Usage == "route-list" || file.Usage == "maxminddb" {
			if err := validateRegistryResourceURL(file.URL); err != nil {
				return contractroute.RegistryCatalog{}, fmt.Errorf("registry file %q: %w", file.ID, err)
			}
		}
		if file.Size < 0 {
			return contractroute.RegistryCatalog{}, fmt.Errorf("registry file %q has negative size", file.ID)
		}
		files = append(files, file)
	}

	return contractroute.RegistryCatalog{
		Registry:      registry,
		SchemaVersion: manifest.SchemaVersion,
		Repository:    manifest.Repository,
		Branch:        manifest.Branch,
		BaseURL:       manifest.BaseURL,
		Files:         files,
	}, nil
}

func resolveRegistryURL(baseURL, filePath string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return "", errors.New("base URL must use http or https")
	}
	base.Path = path.Join(base.Path, filePath)
	return base.String(), nil
}

func validateRegistryResourceURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("resource URL must use http or https")
	}
	if u.Host == "" {
		return errors.New("resource URL host is empty")
	}
	return nil
}

func registryHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(network, addr)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %w", err)
				}
				ctx = netapi.WithContext(ctx)
				return configuration.ProxyChain.Conn(ctx, ad)
			},
		},
	}
}
