package nntp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TLSConfig optionally enables an implicit-TLS NNTP listener.
type TLSConfig struct {
	ListenAddr string
	CertFile   string
	KeyFile    string
	Generated  *GeneratedTLSConfig
}

// GeneratedTLSConfig creates and persists synthetic-only certificate material.
// Do not use this mode for a production service.
type GeneratedTLSConfig struct {
	Directory   string
	DNSNames    []string
	IPAddresses []net.IP
}

// Validate checks that TLS has exactly one certificate source when enabled.
func (config TLSConfig) Validate() error {
	if strings.TrimSpace(config.ListenAddr) == "" {
		if config.CertFile != "" || config.KeyFile != "" || config.Generated != nil {
			return errors.New("TLS certificate configuration requires a TLS listen address")
		}
		return nil
	}
	providedFiles := strings.TrimSpace(config.CertFile) != "" || strings.TrimSpace(config.KeyFile) != ""
	if providedFiles && (strings.TrimSpace(config.CertFile) == "" || strings.TrimSpace(config.KeyFile) == "") {
		return errors.New("both TLS certificate and key files are required")
	}
	if providedFiles && config.Generated != nil {
		return errors.New("TLS file material and generated material are mutually exclusive")
	}
	if !providedFiles && config.Generated == nil {
		return errors.New("TLS requires certificate files or explicit generated test TLS")
	}
	if config.Generated != nil && strings.TrimSpace(config.Generated.Directory) == "" {
		return errors.New("generated TLS requires a certificate directory")
	}
	return nil
}

func (config TLSConfig) load() (*tls.Config, string, error) {
	if config.ListenAddr == "" {
		return nil, "", nil
	}
	certificatePath, keyPath, caPath := config.CertFile, config.KeyFile, ""
	if config.Generated != nil {
		var err error
		certificatePath, keyPath, caPath, err = ensureGeneratedTLS(*config.Generated)
		if err != nil {
			return nil, "", err
		}
	}
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}, caPath, nil
}

func ensureGeneratedTLS(config GeneratedTLSConfig) (certificatePath, keyPath, caPath string, err error) {
	if err := os.MkdirAll(config.Directory, 0o700); err != nil {
		return "", "", "", fmt.Errorf("create generated TLS directory: %w", err)
	}
	certificatePath = filepath.Join(config.Directory, "server.pem")
	keyPath = filepath.Join(config.Directory, "server.key")
	caPath = filepath.Join(config.Directory, "ca.pem")
	caKeyPath := filepath.Join(config.Directory, "ca.key")
	if allFilesExist(certificatePath, keyPath, caPath, caKeyPath) {
		return certificatePath, keyPath, caPath, nil
	}
	if err := removeTLSFiles(certificatePath, keyPath, caPath, caKeyPath); err != nil {
		return "", "", "", err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("generate CA key: %w", err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "e2e-nntp test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", fmt.Errorf("create CA certificate: %w", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		return "", "", "", fmt.Errorf("parse generated CA certificate: %w", err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("generate server key: %w", err)
	}
	dnsNames := append([]string(nil), config.DNSNames...)
	if len(dnsNames) == 0 {
		dnsNames = []string{"localhost"}
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  append([]net.IP(nil), config.IPAddresses...),
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate, &serverKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", fmt.Errorf("create server certificate: %w", err)
	}
	if err := writePEM(caPath, "CERTIFICATE", caDER, 0o644); err != nil {
		return "", "", "", err
	}
	if err := writeECPrivateKey(caKeyPath, caKey); err != nil {
		return "", "", "", err
	}
	if err := writePEM(certificatePath, "CERTIFICATE", serverDER, 0o644); err != nil {
		return "", "", "", err
	}
	if err := writeECPrivateKey(keyPath, serverKey); err != nil {
		return "", "", "", err
	}
	return certificatePath, keyPath, caPath, nil
}

func allFilesExist(paths ...string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

func removeTLSFiles(paths ...string) error {
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove incomplete TLS material: %w", err)
		}
	}
	return nil
}

func writePEM(path, kind string, der []byte, mode os.FileMode) error {
	contents := pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
	if err := os.WriteFile(path, contents, mode); err != nil {
		return fmt.Errorf("write TLS material: %w", err)
	}
	return nil
}

func writeECPrivateKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal TLS key: %w", err)
	}
	return writePEM(path, "EC PRIVATE KEY", der, 0o600)
}
