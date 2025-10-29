package certs_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/takimoto3/app-attest/certs"
)

// generateTestCert creates a temporary self-signed certificate for testing.
func generateTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	return cert
}

// writeTempPEMFile writes the given certificate in PEM format.
func writeTempPEMFile(t *testing.T, cert *x509.Certificate) string {
	t.Helper()

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	path := filepath.Join(t.TempDir(), cert.Subject.CommonName+".pem")
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		t.Fatalf("failed to write PEM file: %v", err)
	}
	return path
}

// writeTempDERFile writes the given certificate in DER format.
func writeTempDERFile(t *testing.T, cert *x509.Certificate) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), cert.Subject.CommonName+".cer")
	if err := os.WriteFile(path, cert.Raw, 0600); err != nil {
		t.Fatalf("failed to write DER file: %v", err)
	}
	return path
}

// writeTempMultiDERFile writes multiple concatenated DER certificates into one file.
func writeTempMultiDERFile(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()

	var combined []byte
	for _, c := range certs {
		combined = append(combined, c.Raw...)
	}
	path := filepath.Join(t.TempDir(), "multi.cer")
	if err := os.WriteFile(path, combined, 0600); err != nil {
		t.Fatalf("failed to write multi DER file: %v", err)
	}
	return path
}

// writeTempFile writes arbitrary data to a temporary file with given extension.
func writeTempFile(t *testing.T, ext string, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "data"+ext)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}

func TestLoadCertFiles(t *testing.T) {
	// Prepare test certificates
	cert1 := generateTestCert(t, "test1")
	cert2 := generateTestCert(t, "test2")

	pemPath := writeTempPEMFile(t, cert1)
	derPath := writeTempDERFile(t, cert1)
	multiDERPath := writeTempMultiDERFile(t, cert1, cert2)
	invalidPath := writeTempFile(t, ".pem", []byte("not a valid certificate"))
	txtPath := writeTempFile(t, ".txt", []byte("unsupported format"))

	tests := []struct {
		name    string
		paths   []string
		wantErr bool
	}{
		{
			name:    "valid PEM file",
			paths:   []string{pemPath},
			wantErr: false,
		},
		{
			name:    "valid single DER file",
			paths:   []string{derPath},
			wantErr: false,
		},
		{
			name:    "valid multiple DER certs in one file",
			paths:   []string{multiDERPath},
			wantErr: false,
		},
		{
			name:    "multiple valid files (PEM + DER)",
			paths:   []string{pemPath, derPath},
			wantErr: false,
		},
		{
			name:    "invalid PEM file",
			paths:   []string{invalidPath},
			wantErr: true,
		},
		{
			name:    "unsupported file extension",
			paths:   []string{txtPath},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := certs.LoadCertFiles(tt.paths...)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pool == nil {
				t.Fatalf("CertPool is nil")
			}

			// Verify at least one of the test subjects exists in the pool
			found := false
			for _, subj := range pool.Subjects() {
				if string(subj) == string(cert1.RawSubject) ||
					string(subj) == string(cert2.RawSubject) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected certificate subject not found in pool")
			}
		})
	}
}
