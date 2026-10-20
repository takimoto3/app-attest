package certs

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// LoadCertFiles loads multiple certificate files (.pem or .cer) into an x509.CertPool.
// It automatically detects whether .cer files are in PEM or DER format.
func LoadCertFiles(paths ...string) (*x509.CertPool, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("at least one certificate file is required")
	}
	pool := x509.NewCertPool()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", path, err)
		}

		switch filepath.Ext(path) {
		case ".pem":
			if ok := pool.AppendCertsFromPEM(data); !ok {
				return nil, fmt.Errorf("no valid certificates found in %s", path)
			}

		case ".cer":
			// Try PEM first
			if ok := pool.AppendCertsFromPEM(data); ok {
				continue
			}
			// Try multiple DER certs
			certs, err := x509.ParseCertificates(data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse DER certificates in %s: %w", path, err)
			}
			if len(certs) == 0 {
				return nil, fmt.Errorf("no certificates found in %s", path)
			}

			for _, cert := range certs {
				pool.AddCert(cert)
			}

		default:
			return nil, fmt.Errorf("unsupported file extension: %s. Expected .pem or .cer", path)
		}
	}
	return pool, nil
}
