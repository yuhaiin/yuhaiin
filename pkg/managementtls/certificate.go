package managementtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const certificateFileName = "management-tls.pem"

// LoadOrCreate returns a persistent self-signed certificate for the management
// listener. The private key is stored in the data directory with owner-only
// permissions so browser certificate exceptions survive service restarts.
func LoadOrCreate(dataDir string, extraNames []string) (tls.Certificate, string, bool, error) {
	if dataDir == "" {
		return tls.Certificate{}, "", false, errors.New("management TLS requires a data directory")
	}

	path := filepath.Join(dataDir, certificateFileName)
	data, err := os.ReadFile(path)
	if err == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			return tls.Certificate{}, "", false, fmt.Errorf("protect management TLS private key: %w", err)
		}
		certificate, fingerprint, err := parseBundle(data)
		return certificate, fingerprint, false, err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, "", false, fmt.Errorf("read management TLS certificate: %w", err)
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return tls.Certificate{}, "", false, fmt.Errorf("create management TLS data directory: %w", err)
	}
	certificatePEM, privateKeyPEM, err := generate(extraNames)
	if err != nil {
		return tls.Certificate{}, "", false, err
	}
	data = append(certificatePEM, privateKeyPEM...)

	temporary, err := os.CreateTemp(dataDir, ".management-tls-*.pem")
	if err != nil {
		return tls.Certificate{}, "", false, fmt.Errorf("create temporary management TLS certificate: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return tls.Certificate{}, "", false, fmt.Errorf("write management TLS certificate: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return tls.Certificate{}, "", false, fmt.Errorf("sync management TLS certificate: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return tls.Certificate{}, "", false, fmt.Errorf("close management TLS certificate: %w", err)
	}

	created := true
	if err := os.Link(temporaryPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return tls.Certificate{}, "", false, fmt.Errorf("persist management TLS certificate: %w", err)
		}
		created = false
		data, err = os.ReadFile(path)
		if err != nil {
			return tls.Certificate{}, "", false, fmt.Errorf("read concurrent management TLS certificate: %w", err)
		}
	} else if err := os.Chmod(path, 0o600); err != nil {
		return tls.Certificate{}, "", false, fmt.Errorf("protect management TLS private key: %w", err)
	}

	certificate, fingerprint, err := parseBundle(data)
	if err != nil {
		return tls.Certificate{}, "", false, err
	}
	return certificate, fingerprint, created, nil
}

// LoadPair loads a configured certificate and key and returns the SHA-256
// fingerprint of its leaf certificate.
func LoadPair(certificatePath, privateKeyPath string) (tls.Certificate, string, error) {
	certificate, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("load management TLS certificate: %w", err)
	}
	if certificate.Leaf == nil {
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return tls.Certificate{}, "", fmt.Errorf("parse management TLS leaf certificate: %w", err)
		}
		certificate.Leaf = leaf
	}
	fingerprint := fingerprint(certificate.Certificate[0])
	return certificate, fingerprint, nil
}

func parseBundle(data []byte) (tls.Certificate, string, error) {
	certificateBlock, rest := pem.Decode(data)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" {
		return tls.Certificate{}, "", errors.New("management TLS file must start with a PEM certificate")
	}
	privateKeyBlock, rest := pem.Decode(rest)
	if privateKeyBlock == nil || privateKeyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return tls.Certificate{}, "", errors.New("management TLS file must contain one certificate and one PKCS#8 private key")
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(certificateBlock),
		pem.EncodeToMemory(privateKeyBlock),
	)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("parse management TLS certificate and key: %w", err)
	}
	if certificate.Leaf == nil {
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return tls.Certificate{}, "", fmt.Errorf("parse management TLS leaf certificate: %w", err)
		}
		certificate.Leaf = leaf
	}
	return certificate, fingerprint(certificate.Certificate[0]), nil
}

func generate(extraNames []string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate management TLS private key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate management TLS serial: %w", err)
	}

	dnsNames, ipAddresses, err := certificateNames(extraNames)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Yuhaiin Management"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create management TLS certificate: %w", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode management TLS private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), nil
}

func certificateNames(extra []string) ([]string, []net.IP, error) {
	names := map[string]struct{}{"localhost": {}}
	addresses := make(map[string]net.IP)
	if hostname, err := os.Hostname(); err == nil && validDNSName(hostname) {
		names[strings.ToLower(hostname)] = struct{}{}
	}
	if interfaceAddresses, err := net.InterfaceAddrs(); err == nil {
		for _, address := range interfaceAddresses {
			prefix, ok := address.(*net.IPNet)
			if !ok || prefix.IP == nil {
				continue
			}
			ip := prefix.IP.To4()
			if ip == nil {
				ip = prefix.IP.To16()
			}
			if ip != nil {
				addresses[ip.String()] = ip
			}
		}
	}
	for _, name := range extra {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if ip := net.ParseIP(name); ip != nil {
			addresses[ip.String()] = ip
			continue
		}
		if !validDNSName(name) {
			return nil, nil, fmt.Errorf("invalid management TLS certificate name %q", name)
		}
		names[strings.ToLower(name)] = struct{}{}
	}

	dnsNames := make([]string, 0, len(names))
	for name := range names {
		dnsNames = append(dnsNames, name)
	}
	slices.Sort(dnsNames)
	ipAddresses := make([]net.IP, 0, len(addresses))
	for _, ip := range addresses {
		ipAddresses = append(ipAddresses, ip)
	}
	slices.SortFunc(ipAddresses, func(a, b net.IP) int { return strings.Compare(a.String(), b.String()) })
	return dnsNames, ipAddresses, nil
}

func validDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.HasSuffix(name, ".") {
		return false
	}
	for label := range strings.SplitSeq(strings.ToLower(name), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789-", char) {
				return false
			}
		}
	}
	return true
}

func fingerprint(certificateDER []byte) string {
	sum := sha256.Sum256(certificateDER)
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))
	var out strings.Builder
	for index := 0; index < len(encoded); index += 2 {
		if index > 0 {
			out.WriteByte(':')
		}
		out.WriteString(encoded[index : index+2])
	}
	return out.String()
}
