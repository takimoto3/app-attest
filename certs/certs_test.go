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

	now := time.Now()

	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
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

func writeTempPEMFileWithExt(t *testing.T, cert *x509.Certificate, ext string) string {
	t.Helper()

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	path := filepath.Join(t.TempDir(), cert.Subject.CommonName+ext)
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		t.Fatalf("failed to write PEM file: %v", err)
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

	pemPath := writeTempPEMFileWithExt(t, cert1, ".pem")
	derPath := writeTempDERFile(t, cert1)
	derPath2 := writeTempDERFile(t, cert2)
	multiDERPath := writeTempMultiDERFile(t, cert1, cert2)
	invalidPEMPath := writeTempFile(t, ".pem", []byte("not a valid certificate"))
	invalidDERPath := writeTempFile(t, ".cer", []byte("not a valid certificate"))
	emptyPEMPath := writeTempFile(t, ".pem", nil)
	txtPath := writeTempFile(t, ".txt", []byte("unsupported format"))
	missingPath := filepath.Join(t.TempDir(), "missing.pem")

	tests := map[string]struct {
		paths     []string
		wantCerts []*x509.Certificate
		wantErr   bool
	}{
		"no files": {
			wantErr: true,
		},
		"valid PEM file": {
			paths:     []string{pemPath},
			wantCerts: []*x509.Certificate{cert1},
		},
		"valid single DER file": {
			paths:     []string{derPath},
			wantCerts: []*x509.Certificate{cert1},
		},
		"valid multiple DER certs in one file": {
			paths:     []string{multiDERPath},
			wantCerts: []*x509.Certificate{cert1, cert2},
		},
		"multiple valid files (PEM + DER)": {
			paths:     []string{pemPath, derPath2},
			wantCerts: []*x509.Certificate{cert1, cert2},
		},
		"PEM certificate in CER file": {
			paths:     []string{writeTempPEMFileWithExt(t, cert2, ".cer")},
			wantCerts: []*x509.Certificate{cert2},
		},
		"invalid PEM file": {
			paths:   []string{invalidPEMPath},
			wantErr: true,
		},
		"invalid DER file": {
			paths:   []string{invalidDERPath},
			wantErr: true,
		},
		"empty PEM file": {
			paths:   []string{emptyPEMPath},
			wantErr: true,
		},
		"missing file": {
			paths:   []string{missingPath},
			wantErr: true,
		},
		"unsupported file extension": {
			paths:   []string{txtPath},
			wantErr: true,
		},
		"valid file followed by missing file": {
			paths:   []string{pemPath, missingPath},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pool, err := certs.LoadCertFiles(tt.paths...)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if pool != nil {
					t.Fatal("expected nil CertPool on error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pool == nil {
				t.Fatal("CertPool is nil")
			}

			subjects := make(map[string]struct{}, len(pool.Subjects()))
			for _, subject := range pool.Subjects() {
				subjects[string(subject)] = struct{}{}
			}

			for _, cert := range tt.wantCerts {
				if _, ok := subjects[string(cert.RawSubject)]; !ok {
					t.Errorf("certificate subject %q not found in pool", cert.Subject.CommonName)
				}
			}
		})
	}
}
