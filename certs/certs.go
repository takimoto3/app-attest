package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// LoadCertFiles loads multiple certificate files (.pem or .cer) into an x509.CertPool.
// It automatically detects whether .cer files are in PEM or DER format.
func LoadCertFiles(paths ...string) (*x509.CertPool, error) {
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
			// Try to decode as PEM first
			block, _ := pem.Decode(data)
			if block != nil && block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("failed to parse PEM certificate %s: %w", path, err)
				}
				pool.AddCert(cert)
				continue
			}
			// Fallback to DER
			cert, err := x509.ParseCertificate(data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse DER certificate %s: %w", path, err)
			}
			pool.AddCert(cert)

		default:
			return nil, fmt.Errorf("unsupported file extension: %s. Expected .pem or .cer", path)
		}
	}
	return pool, nil
}
