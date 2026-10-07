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

func (attr *Attribute) unmarshalOctetString() ([]byte, error) {
	var buf []byte
	if _, err := asn1.Unmarshal(attr.Raw.FullBytes, &buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (attr *Attribute) unmarshalTime() (time.Time, error) {
	b, err := attr.unmarshalOctetString()
	if err != nil {
		return time.Time{}, fmt.Errorf("octet string: %w", err)
	}
	t, err := time.Parse(time.RFC3339, string(b))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse RFC3339 %q: %w", b, err)
	}
	return t, nil
}

// ReceiptVerifier verifies App Attest receipts.
// It checks the PKCS#7 signature and parses the ASN.1 payload.
type ReceiptVerifier struct {
	// RootCertPool holds root CA certificates for signature verification.
	RootCertPool *x509.CertPool

	// MaxAge is the maximum age of a receipt, measured from its creation
	// time. If zero, defaultMaxAge (5 minutes) is used.
	MaxAge time.Duration // Allowed creation delta
}

// NewReceiptVerifier creates a ReceiptVerifier using the provided root CA certificate pool.
func NewReceiptVerifier(pool *x509.CertPool) *ReceiptVerifier {
	return &ReceiptVerifier{RootCertPool: pool, MaxAge: defaultMaxAge}
}

func (v *ReceiptVerifier) Verify(encoded []byte, appID string, pubkey *ecdsa.PublicKey) (*Receipt, error) {
	if len(encoded) == 0 {
		return nil, errors.New("receipt: encoded receipt is empty")
	}
	if appID == "" {
		return nil, errors.New("receipt: appID is empty")
	}
	if pubkey == nil {
		return nil, errors.New("receipt: expected public key is nil")
	}

	r, err := v.verify(encoded, appID, pubkey)
	if err != nil {
		return nil, err
	}
	return r, err
}

// Validate checks that the Receipt matches the expected app ID and public key,
// has a valid type, and was created no more than MaxAge ago.
//
// Deprecated: use ReceiptVerifier.Verify, which verifies the signature and
// validates the receipt in one call.
func (v *ReceiptVerifier) ParseAndVerify(encoded []byte) (*Receipt, error) {
	if v.RootCertPool == nil {
		return nil, errors.New("verifier is not initialized: RootCertPool is nil")
	}
	if len(encoded) == 0 {
		return nil, errors.New("receipt: encoded receipt is empty")
	}

	p7, err := pkcs7.Parse(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7: %w", err)
	}
	if err := p7.VerifyWithChain(v.RootCertPool); err != nil {
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

func (v *ReceiptVerifier) verify(encoded []byte, appID string, pubkey *ecdsa.PublicKey) (*Receipt, error) {
	if v.RootCertPool == nil {
		return nil, errors.New("verifier is not initialized: RootCertPool is nil")
	}
	p7data, err := pkcs7.Parse(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7: %w", err)
	}

	// Apple "Assessing fraud risk" — Verify the receipt:
	// 1. Verify the signature.
	// 2. Evalutate the trustworthiness of the signing certificate up to the Apple public root certificate for App Attest.
	if err := p7data.VerifyWithChain(v.RootCertPool); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	if p7data.Content == nil {
		return nil, errors.New("missing PKCS#7 content")
	}

	// 3. Parse the ASN.1 structure that makes up the payload.
	var attributes []Attribute
	if _, err := asn1.UnmarshalWithParams(p7data.Content, &attributes, "set"); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ASN.1 payload: %w", err)
	}

	receipt := Receipt{MaxAge: defaultMaxAge}
	if err := receipt.Unmarshal(attributes); err != nil {
		return nil, err
	}

	// 4. Verify that the receipt contains the App ID of your app in field 2.
	// Your app’s App ID is the concatenation of your 10-digit Team ID, a period, and the app’s bundle ID.
	if receipt.AppID != appID {
		return nil, fmt.Errorf("app id mismatch: got %q, want %q", receipt.AppID, appID)
	}

	// 5. Verify that the receipt’s creation time, given in field 12,
	// is no more than five minutes old. This helps to thwart replay attacks.
	delta := time.Since(receipt.CreationTime)
	if delta > v.MaxAge {
		return nil, fmt.Errorf("invalid receipt creation time delta=%s (allowed 0–%s)", delta, v.MaxAge)
	}

	// 6. Verify that the attested public key in field 3, encoded as a DER ASN.1 object,
	// matches the one you stored after initial attestation.
	if receipt.PublicKey == nil {
		return nil, errors.New("attested public key missing (field 3)")
	}
	if !receipt.PublicKey.Equal(pubkey) {
		return nil, errors.New("attested public key mismatch (field 3)")
	}

	return &receipt, nil
}

// Receipt holds the extracted fields from an App Attest receipt.
type Receipt struct {
	AppID          string           // ASN.1 Field:2
	PublicKey      *ecdsa.PublicKey // ASN.1 Field:3
	Type           string           // ASN.1 Field:6 "ATTEST" or "RECEIPT"
	CreationTime   time.Time        // ASN.1 Field:12
	NotBefore      time.Time        // ASN.1 Field:19
	ExpirationTime time.Time        // ASN.1 Field:21
	Unknown        []Attribute      // ASN.1 Unknown Fields

	// RiskMetric is field 17: the number of attested keys for the device over
	// the past 30 days. Non-nil for RECEIPT (Verify rejects a RECEIPT without
	// it), nil for ATTEST.
	RiskMetric int // ASN.1 Field:17

	// MaxAge is the allowed creation delta used by Validate.
	//
	// Deprecated: configure ReceiptVerifier.MaxAge instead.
	// Verify ignores this field.
	MaxAge time.Duration // Allowed creation delta
}

// Unmarshal populates the Receipt fields from ASN.1 attributes.
func (r *Receipt) Unmarshal(attributes []Attribute) error {
	for _, attr := range attributes {
		switch attr.Type {
		case 2: // AppID
			// Version 1: AppID is encoded as OCTET STRING containing the string
			bytes, err := attr.unmarshalOctetString()
			if err != nil {
				return fmt.Errorf("failed to unmarshal AppID (field:%d): %w", attr.Type, err)
			}
			r.AppID = string(bytes)
		case 3: // Attested Public Key (X.509 certificate)
			// Apple encodes this field as an OCTET STRING containing a DER-encoded X.509 certificate.
			// The actual ECDSA public key can be extracted from the parsed certificate.
			certDER, err := attr.unmarshalOctetString()
			if err != nil {
				return fmt.Errorf("failed to unmarshal Attested Public Key (field:%d): %w", attr.Type, err)
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
		case 6: // Receipt Type
			bytes, err := attr.unmarshalOctetString()
			if err != nil {
				return fmt.Errorf("failed to unmarshal Receipt Type (field:%d): %w", attr.Type, err)
			}
			r.Type = string(bytes)
		case 12: // Creation Time
			tm, err := attr.unmarshalTime()
			if err != nil {
				return fmt.Errorf("failed to unmarshal Creation Time (field:%d): %w", attr.Type, err)
			}
			r.CreationTime = tm
		case 17: // RiskMetric
			bytes, err := attr.unmarshalOctetString()
			if err != nil {
				return fmt.Errorf("failed to unmarshal RiskMetric (field:%d): %w", attr.Type, err)
			}
			v, err := strconv.Atoi(string(bytes))
			if err != nil {
				return fmt.Errorf("failed to parse RiskMetric string value: %w", err)
			}
			r.RiskMetric = v
		case 19: // Not Before
			tm, err := attr.unmarshalTime()
			if err != nil {
				return fmt.Errorf("failed to unmarshal Not Before (field:%d): %w", attr.Type, err)
			}
			r.NotBefore = tm
		case 21: // Expiration Time
			tm, err := attr.unmarshalTime()
			if err != nil {
				return fmt.Errorf("failed to unmarshal Expiration Time (field:%d): %w", attr.Type, err)
			}
			r.ExpirationTime = tm
		default:
			r.Unknown = append(r.Unknown, attr)
		}
	}
	return nil
}

// Validate checks that the Receipt matches the expected app ID and public key,
// has a valid type, and was created no more than MaxAge ago.
//
// Deprecated: use ReceiptVerifier.Verify, which verifies the signature and
// validates the receipt in one call.
func (r *Receipt) Validate(appID string, publicKey *ecdsa.PublicKey) error {
	if r.AppID != appID {
		return fmt.Errorf("app id mismatch: got %q, want %q", r.AppID, appID)
	}
	if publicKey == nil {
		return errors.New("expected public key is nil")
	}
	if r.PublicKey == nil {
		return errors.New("attested public key missing (field 3)")
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

// Dump returns a map of the receipt fields for debugging.
//
// Deprecated: Dump is a debugging aid and its output is no longer
// extended. Format the exported fields of Receipt directly.
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
