// Package updatercore implements signed manifest and artifact update logic for
// Go CLIs.
package updatercore

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Manifest describes a multi-target signed release payload.
// Signature covers the JSON payload with the Signature field cleared.
type Manifest struct {
	Name        string              `json:"name"`
	Channel     string              `json:"channel"`
	Version     string              `json:"version"`
	BuildNumber int                 `json:"build_number"`
	ReleasedAt  string              `json:"released_at"`
	Targets     []ManifestTarget    `json:"targets"`
	Signature   string              `json:"signature"`
	Signatures  []ManifestSignature `json:"signatures,omitempty"`
}

// ManifestTarget describes a single platform artifact.
type ManifestTarget struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// ManifestSignature captures a single signature entry for the manifest payload.
type ManifestSignature struct {
	KeyID string `json:"key_id"`
	Algo  string `json:"algo"`
	Value string `json:"value"`
}

// Client encapsulates shared update logic for Go CLIs.
type Client struct {
	ProductName    string
	ManifestURL    string
	CurrentVersion string
	PublicKey      []byte
	HTTPClient     *http.Client
	SOCKS5Proxy    string
}

// UpdateOptions controls a single update check/apply flow.
type UpdateOptions struct {
	ManifestURL   string
	CheckOnly     bool
	ManifestBytes []byte
	SkipVerify    bool
}

// Result captures the outcome of an update attempt.
type Result struct {
	Updated          bool
	CurrentBuild     int
	NewBuild         int
	Message          string
	WindowsStagedBin string
	CheckOnly        bool
}

// Update downloads and applies an update if a newer build exists. When CheckOnly
// is true, it verifies availability without touching the local binary.
func (c *Client) Update(ctx context.Context, opts UpdateOptions) (Result, error) {
	var res Result
	skipVerify := opts.SkipVerify
	if !skipVerify && len(c.PublicKey) == 0 {
		return res, errors.New("update public key is not embedded; rebuild with a signed release configuration")
	}
	manifestURL := opts.ManifestURL
	if manifestURL == "" {
		manifestURL = c.ManifestURL
	}
	if manifestURL == "" {
		return res, errors.New("manifest URL is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	client := c.resolveHTTPClient()
	currentBuild := parseBuildNumber(c.CurrentVersion)
	res.CurrentBuild = currentBuild
	res.CheckOnly = opts.CheckOnly

	var (
		manifest *Manifest
		target   *ManifestTarget
		err      error
	)
	if len(opts.ManifestBytes) > 0 {
		manifest, err = ParseManifest(opts.ManifestBytes)
		if err != nil {
			return res, fmt.Errorf("parse manifest: %w", err)
		}
		if !skipVerify {
			if err := manifest.VerifySignature(c.PublicKey); err != nil {
				return res, err
			}
		}
		var ok bool
		target, ok = manifest.FindTarget(runtime.GOOS, runtime.GOARCH)
		if !ok {
			return res, fmt.Errorf("manifest missing target for %s/%s", runtime.GOOS, runtime.GOARCH)
		}
	} else {
		manifestCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		manifest, target, err = fetchManifest(manifestCtx, client, manifestURL, c.PublicKey, skipVerify)
		if err != nil {
			return res, err
		}
	}
	if err != nil {
		return res, err
	}
	res.NewBuild = manifest.BuildNumber
	if manifest.BuildNumber <= currentBuild {
		res.Message = fmt.Sprintf("%s already at build %d", c.productLabel(), currentBuild)
		return res, nil
	}
	if opts.CheckOnly {
		res.Message = fmt.Sprintf("Update available: build %d → %d (check only)", currentBuild, manifest.BuildNumber)
		return res, nil
	}

	archivePath, artifactName, err := downloadArtifact(ctx, client, manifestURL, target)
	if err != nil {
		return res, err
	}
	defer os.Remove(archivePath)

	binaryPath, err := extractSingleBinary(archivePath, artifactName)
	if err != nil {
		return res, err
	}
	defer os.Remove(binaryPath)

	stagedPath, err := applyBinary(binaryPath)
	if err != nil {
		return res, err
	}

	res.Updated = true
	res.WindowsStagedBin = stagedPath
	res.Message = fmt.Sprintf("Updated %s from build %d to %d", c.productLabel(), currentBuild, manifest.BuildNumber)
	return res, nil
}

func (c *Client) productLabel() string {
	if strings.TrimSpace(c.ProductName) == "" {
		return "product"
	}
	return c.ProductName
}

// ParseManifest loads a manifest from JSON bytes without verifying the signature.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// SignedPayload returns the canonical JSON that was signed (Signature field cleared).
func (m Manifest) SignedPayload() ([]byte, error) {
	m.Signature = ""
	m.Signatures = nil
	return json.Marshal(m)
}

// FindTarget returns the target matching the provided GOOS/GOARCH combo.
func (m *Manifest) FindTarget(goos, goarch string) (*ManifestTarget, bool) {
	for i := range m.Targets {
		t := &m.Targets[i]
		if strings.EqualFold(t.OS, goos) && strings.EqualFold(t.Arch, goarch) {
			return t, true
		}
	}
	return nil, false
}

// VerifySignature checks the manifest's signature against the provided PEM public key.
func (m *Manifest) VerifySignature(pubPEM []byte) error {
	signatures, err := m.effectiveSignatures()
	if err != nil {
		return err
	}
	pub, err := parseRSAPublicKey(pubPEM)
	if err != nil {
		return err
	}
	payload, err := m.SignedPayload()
	if err != nil {
		return fmt.Errorf("marshal payload for verification: %w", err)
	}
	var lastErr error
	for _, sig := range signatures {
		if err := verifySignatureWithKey(pub, sig, payload); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("manifest signature missing")
	}
	return lastErr
}

// VerifyWithKeyring tries every signature against matching keys in the keyring.
// It returns the key ID that successfully validated the manifest.
func (m *Manifest) VerifyWithKeyring(keyring map[string][]byte) (string, error) {
	signatures, err := m.effectiveSignatures()
	if err != nil {
		return "", err
	}
	if len(keyring) == 0 {
		return "", errors.New("keyring empty")
	}
	payload, err := m.SignedPayload()
	if err != nil {
		return "", fmt.Errorf("marshal payload for verification: %w", err)
	}
	var lastErr error
	for _, sig := range signatures {
		var candidates [][]byte
		if sig.KeyID != "" {
			if pem, ok := keyring[sig.KeyID]; ok {
				candidates = append(candidates, pem)
			} else {
				continue
			}
		} else {
			for _, pem := range keyring {
				candidates = append(candidates, pem)
			}
		}
		for _, pem := range candidates {
			pub, err := parseRSAPublicKey(pem)
			if err != nil {
				lastErr = err
				continue
			}
			if err := verifySignatureWithKey(pub, sig, payload); err == nil {
				return sig.KeyID, nil
			} else {
				lastErr = err
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("manifest signature verification failed: no matching keys")
	}
	return "", lastErr
}

func (m *Manifest) effectiveSignatures() ([]ManifestSignature, error) {
	if len(m.Signatures) > 0 {
		return m.Signatures, nil
	}
	if strings.TrimSpace(m.Signature) == "" {
		return nil, errors.New("manifest signature missing")
	}
	return []ManifestSignature{{
		Algo:  "rsa-pss-sha256",
		Value: m.Signature,
	}}, nil
}

func parseRSAPublicKey(pubPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("invalid PEM-encoded public key")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return pub, nil
}

func verifySignatureWithKey(pub *rsa.PublicKey, sig ManifestSignature, payload []byte) error {
	if sig.Algo != "" && !strings.EqualFold(sig.Algo, "rsa-pss-sha256") {
		return fmt.Errorf("unsupported signature algo %q", sig.Algo)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	digest := sha256.Sum256(payload)
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sigBytes, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		return fmt.Errorf("manifest signature verification failed: %w", err)
	}
	return nil
}

func fetchManifest(ctx context.Context, client *http.Client, manifestURL string, publicKey []byte, skipVerify bool) (*Manifest, *ManifestTarget, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("manifest download failed: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	manifest, err := ParseManifest(data)
	if err != nil {
		return nil, nil, err
	}
	if !skipVerify {
		if err := manifest.VerifySignature(publicKey); err != nil {
			return nil, nil, err
		}
	}
	target, ok := manifest.FindTarget(runtime.GOOS, runtime.GOARCH)
	if !ok {
		return nil, nil, fmt.Errorf("no artifact for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return manifest, target, nil
}

func downloadArtifact(ctx context.Context, client *http.Client, manifestURL string, target *ManifestTarget) (string, string, error) {
	mu, err := url.Parse(manifestURL)
	if err != nil {
		return "", "", err
	}
	mu.Path = path.Join(path.Dir(mu.Path), target.File)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mu.String(), nil)
	if err != nil {
		return "", "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("download failed: %s", resp.Status)
	}
	tmp, err := os.CreateTemp("", "response-runtime-updater-*")
	if err != nil {
		return "", "", err
	}
	defer tmp.Close()
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		return "", "", err
	}
	return tmp.Name(), filepath.Base(target.File), nil
}

func extractSingleBinary(archivePath, artifactName string) (string, error) {
	switch strings.ToLower(filepath.Ext(artifactName)) {
	case ".zip":
		return extractZip(archivePath, artifactName)
	case ".gz":
		return extractTarGz(archivePath, artifactName)
	default:
		return "", fmt.Errorf("unsupported archive format for %s", artifactName)
	}
}

func extractZip(archivePath, artifactName string) (string, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer reader.Close()
	var target *zip.File
	var fallback *zip.File
	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if fallback == nil {
			fallback = f
		}
		if filepath.Base(f.Name) == artifactName {
			target = f
			break
		}
	}
	if target == nil {
		target = fallback
	}
	if target == nil {
		return "", fmt.Errorf("zip archive missing file %s", artifactName)
	}
	rc, err := target.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	out, err := os.CreateTemp("", "response-runtime-updater-bin-*")
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, rc); err != nil {
		return "", err
	}
	if err := out.Chmod(0o755); err != nil {
		return "", err
	}
	return out.Name(), nil
}

func extractTarGz(archivePath, artifactName string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	var fallbackData []byte
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if filepath.Base(header.Name) != artifactName && artifactName != "" {
			if len(fallbackData) == 0 {
				buf := bytes.Buffer{}
				if _, err := io.Copy(&buf, tr); err != nil {
					return "", err
				}
				fallbackData = buf.Bytes()
			}
			continue
		}
		out, err := os.CreateTemp("", "response-runtime-updater-bin-*")
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return "", err
		}
		if err := out.Close(); err != nil {
			return "", err
		}
		if err := os.Chmod(out.Name(), 0o755); err != nil {
			return "", err
		}
		return out.Name(), nil
	}
	if len(fallbackData) > 0 {
		out, err := os.CreateTemp("", "response-runtime-updater-bin-*")
		if err != nil {
			return "", err
		}
		if _, err := out.Write(fallbackData); err != nil {
			out.Close()
			return "", err
		}
		if err := out.Close(); err != nil {
			return "", err
		}
		if err := os.Chmod(out.Name(), 0o755); err != nil {
			return "", err
		}
		return out.Name(), nil
	}
	return "", fmt.Errorf("tar.gz archive missing %s", artifactName)
}

func applyBinary(stagedPath string) (string, error) {
	currentPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	backupPath := currentPath + ".bak"
	if err := os.Rename(currentPath, backupPath); err != nil {
		return "", err
	}
	if err := os.Rename(stagedPath, currentPath); err != nil {
		_ = os.Rename(backupPath, currentPath)
		return "", err
	}
	if runtime.GOOS == "windows" {
		return currentPath, nil
	}
	return "", nil
}

func parseBuildNumber(version string) int {
	parts := strings.Split(version, "+")
	if len(parts) < 2 {
		return 0
	}
	n, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return 0
	}
	return n
}

func (c *Client) resolveHTTPClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if strings.TrimSpace(c.SOCKS5Proxy) != "" {
		dialer, err := proxy.SOCKS5("tcp", strings.TrimSpace(c.SOCKS5Proxy), nil, proxy.Direct)
		if err == nil {
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
	}
	return &http.Client{Transport: transport}
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
