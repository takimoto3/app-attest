package receipt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/takimoto3/app-attest/certs"
	"github.com/takimoto3/app-attest/fraud/receipt"
	"github.com/takimoto3/app-attest/testutils"
	"github.com/tenntenn/testtime"
)

func ParseECDSAPublicKeyFromPEM(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not ECDSA public key")
	}

	return pubKey, nil
}

func TestReceiptVerifier_ParseAndVerify(t *testing.T) {
	now, err := time.Parse(time.RFC3339, "2021-01-23T12:27:41Z")
	if err != nil {
		t.Fatal(err)
	}

	// Set a default valid time for most tests (before certificate expiration)
	testtime.SetTime(t, now)

	// load JSON fixture
	testData, err := testutils.LoadTestData()
	if err != nil {
		t.Fatal(err)
	}

	pool, err := certs.LoadCertFiles("testdata/AppleRootCA-G3.cer")
	if err != nil {
		t.Fatal(err)
	}

	verifier := receipt.NewReceiptVerifier(pool)

	data := testutils.DecodeB64(testData.Receipt[1].ReceiptBase64)
	receipt, err := verifier.ParseAndVerify(data)
	if err != nil {
		t.Error(err)
	}
	if receipt == nil {
		t.Fatal("receipt is nil")
	}

	appID := testData.Receipt[1].TeamIdentifier + "." + testData.Receipt[1].BundleIdentifier
	pubkey, err := ParseECDSAPublicKeyFromPEM(testData.Receipt[1].PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	err = receipt.Validate(appID, pubkey)
	if err != nil {
		t.Fatal(err)
	}

	// Advance the test time to exceed the receipt's MaxAge (using real receipt data)
	// This should cause Validate to return an "invalid receipt creation time delta" error
	testtime.SetTime(t, time.Date(2021, 1, 23, 12, 32, 41, 0, time.UTC))

	err = receipt.Validate(appID, pubkey)
	if err == nil {
		t.Fatal("expected error due to receipt creation time exceeding MaxAge")
	}
	if !strings.HasPrefix(err.Error(), "invalid receipt creation time delta=") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Helper: create ASN.1 OCTET STRING as raw attribute
func mustASN1OctetString(data []byte) receipt.Attribute {
	raw, err := asn1.Marshal(data)
	if err != nil {
		panic(err)
	}
	return receipt.Attribute{
		Type: 0, // overridden in test
		Raw:  asn1.RawValue{FullBytes: raw},
	}
}

// Helper: DER bytes for dummy ECDSA public key
func mustSelfSignedCert() []byte {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}

	return certDER
}

// Helper: return map keys as slice
func keys(m map[string]any) []string {
	k := make([]string, 0, len(m))
	for key := range m {
		k = append(k, key)
	}
	return k
}

func TestReceipt_Unmarshal(t *testing.T) {
	now := time.Now()
	certDER := mustSelfSignedCert()

	cases := map[string]struct {
		attributes []receipt.Attribute
		wantErr    bool
	}{
		"AllFieldsValid": {
			attributes: []receipt.Attribute{
				{Type: 2, Raw: mustASN1OctetString([]byte("com.example.app")).Raw},
				{Type: 3, Raw: mustASN1OctetString(certDER).Raw},
				{Type: 6, Raw: mustASN1OctetString([]byte("ATTEST")).Raw},
				{Type: 12, Raw: mustASN1OctetString([]byte(now.Format(time.RFC3339))).Raw},
				{Type: 17, Raw: mustASN1OctetString([]byte("42")).Raw},
				{Type: 99, Raw: mustASN1OctetString([]byte("unknown")).Raw}, // Unknown
			},
			wantErr: false,
		},
		"InvalidCreationTime": {
			attributes: []receipt.Attribute{
				{Type: 12, Raw: mustASN1OctetString([]byte("invalid-time")).Raw},
			},
			wantErr: true,
		},
		"InvalidRiskMetric": {
			attributes: []receipt.Attribute{
				{Type: 17, Raw: mustASN1OctetString([]byte("NaN")).Raw},
			},
			wantErr: true,
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			r := &receipt.Receipt{MaxAge: 5 * time.Minute}
			err := r.Unmarshal(tc.attributes)
			if tc.wantErr && err == nil {
				t.Fatalf("expected Unmarshal error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected Unmarshal error: %v", err)
			}
		})
	}
}

func TestReceipt_Validate(t *testing.T) {
	now := time.Now()
	pubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(2)}

	baseReceipt := &receipt.Receipt{
		AppID:        "com.example.app",
		PublicKey:    pubKey,
		Type:         "ATTEST",
		CreationTime: now,
		MaxAge:       5 * time.Minute,
		RiskMetric:   42,
	}

	cases := map[string]struct {
		modify  func(*receipt.Receipt)
		wantErr bool
	}{
		"ValidReceipt": {modify: func(r *receipt.Receipt) {}, wantErr: false},
		"AppIDMismatch": {
			modify:  func(r *receipt.Receipt) { r.AppID = "com.other.app" },
			wantErr: true,
		},
		"PublicKeyMismatch": {
			modify: func(r *receipt.Receipt) {
				r.PublicKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(2), Y: big.NewInt(3)}
			},
			wantErr: true,
		},
		"InvalidType": {
			modify:  func(r *receipt.Receipt) { r.Type = "INVALID" },
			wantErr: true,
		},
		"CreationTimeExceeded": {
			modify:  func(r *receipt.Receipt) { r.CreationTime = now.Add(-10 * time.Minute) },
			wantErr: true,
		},
		"CreationTimeFuture": {
			modify:  func(r *receipt.Receipt) { r.CreationTime = now.Add(10 * time.Minute) },
			wantErr: true,
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			copy := *baseReceipt
			tc.modify(&copy)
			err := copy.Validate("com.example.app", pubKey)
			if tc.wantErr && err == nil {
				t.Fatalf("expected Validate error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected Validate error: %v", err)
			}
		})
	}
}

func TestReceipt_Dump(t *testing.T) {
	now := time.Now()
	pubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(2)}

	r := &receipt.Receipt{
		AppID:        "com.example.app",
		PublicKey:    pubKey,
		Type:         "ATTEST",
		CreationTime: now,
		MaxAge:       5 * time.Minute,
		RiskMetric:   42,
		Unknown: []receipt.Attribute{
			{Type: 99, Raw: mustASN1OctetString([]byte("unknown")).Raw},
		},
	}

	// Dump all fields
	all := r.Dump()
	expectedKeys := []string{"AppID", "Type", "CreationTime", "RiskMetric", "PublicKeyDER", "Unknown"}
	for _, k := range expectedKeys {
		if _, ok := all[k]; !ok {
			t.Fatalf("expected key %q in Dump output", k)
		}
	}

	// Dump only unknown fields
	unknownOnly := r.Dump(true)
	if diff := cmp.Diff([]string{"Unknown"}, keys(unknownOnly)); diff != "" {
		t.Fatalf("Dump unknown only keys mismatch (-want +got):\n%s", diff)
	}
}
