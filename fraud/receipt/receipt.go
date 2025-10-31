package receipt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/smallstep/pkcs7"
)

const defaultMaxAge = 5 * time.Minute

// Attribute represents a single ASN.1 attribute in an App Attest receipt.
type Attribute struct {
	Type    int
	Version int
	Raw     asn1.RawValue
}

// ReceiptVerifier verifies App Attest receipts.
// It checks the PKCS#7 signature and parses the ASN.1 payload.
type ReceiptVerifier struct {
	// RootCertPool holds root CA certificates for signature verification.
	RootCertPool *x509.CertPool
}

// NewReceiptVerifier creates a ReceiptVerifier using the provided root CA certificate pool.
func NewReceiptVerifier(pool *x509.CertPool) *ReceiptVerifier {
	return &ReceiptVerifier{RootCertPool: pool}
}

// ParseAndVerify parses a PKCS#7-encoded receipt, verifies its signature,
// and extracts fields into a Receipt.
func (rv *ReceiptVerifier) ParseAndVerify(encoded []byte) (*Receipt, error) {
	if rv.RootCertPool == nil {
		return nil, errors.New("verifier is not initialized: RootCertPool is nil")
	}
	p7, err := pkcs7.Parse(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7: %w", err)
	}
	if err := p7.VerifyWithChain(rv.RootCertPool); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	if p7.Content == nil {
		return nil, errors.New("missing PKCS#7 content")
	}

	var attributes []Attribute
	if _, err := asn1.UnmarshalWithParams(p7.Content, &attributes, "set"); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ASN.1 payload: %w", err)
	}

	receipt := Receipt{MaxAge: defaultMaxAge}
	if err := receipt.Unmarshal(attributes); err != nil {
		return nil, err
	}
	return &receipt, nil
}

// Receipt holds the extracted fields from an App Attest receipt.
type Receipt struct {
	AppID        string           // ASN.1 Field:2
	PublicKey    *ecdsa.PublicKey // ASN.1 Field:3
	Type         string           // ASN.1 Field:6 "ATTEST" or "RECEIPT"
	CreationTime time.Time        // ASN.1 Field:12
	RiskMetric   int              // ASN.1 Field:17
	Unknown      []Attribute      // ASN.1 Unknown Fields

	// Validation Parameters
	MaxAge time.Duration // Allowed creation delta
}

// Unmarshal populates the Receipt fields from ASN.1 attributes.
func (r *Receipt) Unmarshal(attributes []Attribute) error {
	for _, attr := range attributes {
		var err error

		var buf []byte
		switch attr.Type {
		case 2: // AppID
			// Version 1: AppID is encoded as OCTET STRING containing the string
			if _, err := asn1.Unmarshal(attr.Raw.FullBytes, &buf); err != nil {
				return fmt.Errorf("failed to unmarshal appID (field 2): %w", err)
			}
			r.AppID = string(buf)
		case 3: // Attested Public Key (X.509 certificate)
			// Apple encodes this field as an OCTET STRING containing a DER-encoded X.509 certificate.
			// The actual ECDSA public key can be extracted from the parsed certificate.
			var certDER []byte
			if _, err := asn1.Unmarshal(attr.Raw.FullBytes, &certDER); err != nil {
				return fmt.Errorf("failed to unmarshal attested certificate OCTET STRING: %w", err)
			}
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				return fmt.Errorf("failed to parse attested certificate: %w", err)
			}
			pubkey, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return errors.New("parsed attested key is unsupported type (expected ECDSA)")
			}
			r.PublicKey = pubkey
		case 6:
			if _, err := asn1.Unmarshal(attr.Raw.FullBytes, &buf); err != nil {
				return fmt.Errorf("failed to unmarshal type (field 6): %w", err)
			}
			r.Type = string(buf)
		case 12:
			if _, err = asn1.Unmarshal(attr.Raw.FullBytes, &buf); err != nil {
				return fmt.Errorf("failed to unmarshal creationTime (field 12): %w", err)
			}
			r.CreationTime, err = time.Parse(time.RFC3339, string(buf))
			if err != nil {
				return fmt.Errorf("failed to parse creation time: %w", err)
			}
		case 17: // RiskMetric
			if _, err := asn1.Unmarshal(attr.Raw.FullBytes, &buf); err != nil {
				return fmt.Errorf("failed to unmarshal RiskMetric as OCTET STRING: %w", err)
			}
			v, err := strconv.Atoi(string(buf))
			if err != nil {
				return fmt.Errorf("failed to parse RiskMetric string value: %w", err)
			}
			r.RiskMetric = v
		default:
			r.Unknown = append(r.Unknown, attr)
		}
	}
	return nil
}

// Validate checks that the Receipt matches the expected app ID and public key,
// has a valid type, and is within the allowed MaxAge.
func (r *Receipt) Validate(appID string, publicKey *ecdsa.PublicKey) error {
	if r.AppID != appID {
		return fmt.Errorf("app id mismatch: got %q, want %q", r.AppID, appID)
	}
	if !r.PublicKey.Equal(publicKey) {
		return errors.New("attested public key mismatch (field 3)")
	}
	if r.Type != "ATTEST" && r.Type != "RECEIPT" {
		return fmt.Errorf("invalid receipt type (field 6): %q", r.Type)
	}

	delta := time.Since(r.CreationTime)
	if delta < 0 || delta > r.MaxAge {
		return fmt.Errorf("invalid receipt creation time delta=%s (allowed 0–%s)", delta, r.MaxAge)
	}
	return nil
}

func (r *Receipt) Dump(opts ...bool) map[string]any {
	unknownOnly := false
	if len(opts) > 0 {
		unknownOnly = opts[0]
	}

	out := make(map[string]any)

	if !unknownOnly {
		out["AppID"] = r.AppID
		out["Type"] = r.Type
		out["CreationTime"] = r.CreationTime
		out["RiskMetric"] = r.RiskMetric
		if r.PublicKey != nil {
			der, _ := x509.MarshalPKIXPublicKey(r.PublicKey)
			out["PublicKeyDER"] = fmt.Sprintf("%X", der)
		}
	}

	if len(r.Unknown) > 0 {
		unknown := make([]map[string]string, len(r.Unknown))
		for i, attr := range r.Unknown {
			unknown[i] = map[string]string{
				"Type": fmt.Sprintf("%d", attr.Type),
				"Raw":  fmt.Sprintf("%X", attr.Raw.FullBytes),
			}
		}
		out["Unknown"] = unknown
	}

	return out
}
