package receipt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/smallstep/pkcs7"
	"github.com/takimoto3/app-attest/fraud/receipt"
)

// --- self-contained PKI helpers for synthetic (non-Apple) test receipts ---

type testPKI struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	leafCert *x509.Certificate
	leafKey  *ecdsa.PrivateKey
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootTmpl, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return &testPKI{rootCert: rootCert, rootKey: rootKey, leafCert: leafCert, leafKey: leafKey}
}

func (pki *testPKI) certPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(pki.rootCert)
	return pool
}

// attestedCertDER creates a leaf certificate (signed by the test root)
// whose public key stands in for App Attest's attested public key
// (field 3). It is intentionally a separate cert from the PKCS7 signer
// leaf, mirroring how Apple's receipt structure works.
func (pki *testPKI) attestedCertDER(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Attested Key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.rootCert, pub, pki.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// der wraps a set of ASN.1 attributes in a PKCS7 SignedData
// envelope, signed by the given signer cert/key — standing in for
// Apple's receipt-signing certificate.
func der(t *testing.T, signerCert *x509.Certificate, signerKey *ecdsa.PrivateKey, attributes ...receipt.Attribute) []byte {
	t.Helper()

	payload, err := asn1.MarshalWithParams(attributes, "set")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pkcs7.NewSignedData(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.AddSigner(signerCert, signerKey, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	der, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func tamperLastByte(data []byte) []byte {
	data[len(data)-1] ^= 0xFF
	return data
}

func TestReceiptVerifier_Verify(t *testing.T) {
	pki := newTestPKI(t)

	correctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certDER := pki.attestedCertDER(t, &correctKey.PublicKey)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	rootCA := pki.certPool()

	validData := der(t, pki.leafCert, pki.leafKey,
		receipt.Attribute{Type: 2, Raw: mustASN1OctetString([]byte("com.example.app")).Raw},
		receipt.Attribute{Type: 3, Raw: mustASN1OctetString(certDER).Raw},
		receipt.Attribute{Type: 6, Raw: mustASN1OctetString([]byte("RECEIPT")).Raw},
		receipt.Attribute{Type: 12, Raw: mustASN1OctetString([]byte(now.Add(-time.Minute).Format(time.RFC3339))).Raw},
		receipt.Attribute{Type: 17, Raw: mustASN1OctetString([]byte("42")).Raw},
	)

	tests := map[string]struct {
		certPool *x509.CertPool
		data     []byte
		appID    string
		pubkey   *ecdsa.PublicKey
		want     *receipt.Receipt
		wantErr  *wantError
	}{
		"valid receipt": {
			certPool: rootCA,
			data:     validData,
			appID:    "com.example.app",
			pubkey:   &correctKey.PublicKey,
			want: &receipt.Receipt{
				AppID:        "com.example.app",
				PublicKey:    &correctKey.PublicKey,
				Type:         "RECEIPT",
				CreationTime: now.Add(-time.Minute).Truncate(time.Second),
				RiskMetric:   42,
			},
		},
		"expired creation time": {
			certPool: rootCA,
			data: der(t, pki.leafCert, pki.leafKey,
				receipt.Attribute{Type: 2, Raw: mustASN1OctetString([]byte("com.example.app")).Raw},
				receipt.Attribute{Type: 3, Raw: mustASN1OctetString(certDER).Raw},
				receipt.Attribute{Type: 6, Raw: mustASN1OctetString([]byte("RECEIPT")).Raw},
				receipt.Attribute{Type: 12, Raw: mustASN1OctetString([]byte(now.Add(-10 * time.Minute).Format(time.RFC3339))).Raw}, // exceeds the 5-minute limit
				receipt.Attribute{Type: 17, Raw: mustASN1OctetString([]byte("42")).Raw},
			),
			appID:   "com.example.app",
			pubkey:  &correctKey.PublicKey,
			wantErr: expectError("invalid receipt creation time delta="),
		},
		"creation time in the future": {
			certPool: rootCA,
			data: der(t, pki.leafCert, pki.leafKey,
				receipt.Attribute{Type: 2, Raw: mustASN1OctetString([]byte("com.example.app")).Raw},
				receipt.Attribute{Type: 3, Raw: mustASN1OctetString(certDER).Raw},
				receipt.Attribute{Type: 6, Raw: mustASN1OctetString([]byte("RECEIPT")).Raw},
				receipt.Attribute{Type: 12, Raw: mustASN1OctetString([]byte(now.Add(time.Minute).Format(time.RFC3339))).Raw},
				receipt.Attribute{Type: 17, Raw: mustASN1OctetString([]byte("42")).Raw},
			),
			appID:  "com.example.app",
			pubkey: &correctKey.PublicKey,
			want: &receipt.Receipt{
				AppID:        "com.example.app",
				PublicKey:    &correctKey.PublicKey,
				Type:         "RECEIPT",
				CreationTime: now.Add(time.Minute).Truncate(time.Second),
				RiskMetric:   42,
			},
		},
		"app id mismatch": {
			certPool: rootCA,
			data:     validData,
			appID:    "other.bundle.id",
			pubkey:   &correctKey.PublicKey,
			wantErr:  expectError("app id mismatch"),
		},
		"public key mismatch": {
			certPool: rootCA,
			data:     validData,
			appID:    "com.example.app",
			pubkey:   &otherKey.PublicKey, // does not match attested cert (field 3)
			wantErr:  expectError("attested public key mismatch"),
		},
		"missing attested public key (field 3)": {
			certPool: rootCA,
			data: der(t, pki.leafCert, pki.leafKey,
				receipt.Attribute{Type: 2, Raw: mustASN1OctetString([]byte("com.example.app")).Raw},
				receipt.Attribute{Type: 6, Raw: mustASN1OctetString([]byte("RECEIPT")).Raw},
				receipt.Attribute{Type: 12, Raw: mustASN1OctetString([]byte(now.Add(-time.Minute).Format(time.RFC3339))).Raw},
				receipt.Attribute{Type: 17, Raw: mustASN1OctetString([]byte("42")).Raw},
			),
			appID:   "com.example.app",
			pubkey:  &correctKey.PublicKey,
			wantErr: expectError("attested public key missing (field 3)"),
		},
		"invalid receipt type": {
			certPool: rootCA,
			data: der(t, pki.leafCert, pki.leafKey,
				receipt.Attribute{Type: 2, Raw: mustASN1OctetString([]byte("com.example.app")).Raw},
				receipt.Attribute{Type: 3, Raw: mustASN1OctetString(certDER).Raw},
				receipt.Attribute{Type: 6, Raw: mustASN1OctetString([]byte("BOGUS")).Raw}, // ← invalid type
				receipt.Attribute{Type: 12, Raw: mustASN1OctetString([]byte(now.Add(-time.Minute).Format(time.RFC3339))).Raw},
				receipt.Attribute{Type: 17, Raw: mustASN1OctetString([]byte("42")).Raw},
			),
			appID:  "com.example.app",
			pubkey: &correctKey.PublicKey,
			want: &receipt.Receipt{
				AppID:        "com.example.app",
				PublicKey:    &correctKey.PublicKey,
				Type:         "BOGUS",
				CreationTime: now.Add(-time.Minute).Truncate(time.Second),
				RiskMetric:   42,
			},
		},
		"tampered payload invalidates signature": {
			certPool: rootCA,
			data: tamperLastByte(der(t, pki.leafCert, pki.leafKey, // tampered
				receipt.Attribute{Type: 2, Raw: mustASN1OctetString([]byte("com.example.app")).Raw},
				receipt.Attribute{Type: 3, Raw: mustASN1OctetString(certDER).Raw},
				receipt.Attribute{Type: 6, Raw: mustASN1OctetString([]byte("RECEIPT")).Raw},
				receipt.Attribute{Type: 12, Raw: mustASN1OctetString([]byte(now.Add(-time.Minute).Format(time.RFC3339))).Raw},
				receipt.Attribute{Type: 17, Raw: mustASN1OctetString([]byte("42")).Raw},
			)),
			appID:   "com.example.app",
			pubkey:  &correctKey.PublicKey,
			wantErr: expectError("signature verification failed"),
		},
		"untrusted root": {
			certPool: newTestPKI(t).certPool(), // untrusted root
			data:     validData,
			appID:    "com.example.app",
			pubkey:   &correctKey.PublicKey,
			wantErr:  expectError("signature verification failed"),
		},
		"nil root cert pool": {
			certPool: nil,
			data:     validData,
			appID:    "com.example.app",
			pubkey:   &correctKey.PublicKey,
			wantErr:  expectError("RootCertPool is nil"),
		},
		"nil public key": {
			certPool: rootCA,
			data:     validData,
			appID:    "com.example.app",
			pubkey:   nil,
			wantErr:  expectError("expected public key is nil"),
		},
		"malformed PKCS7 container": {
			certPool: rootCA,
			data:     []byte("not a valid pkcs7 der structure"),
			appID:    "com.example.app",
			pubkey:   &correctKey.PublicKey,
			wantErr:  expectError("failed to parse PKCS#7"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			verifier := receipt.NewReceiptVerifier(tt.certPool)
			got, err := verifier.Verify(tt.data, tt.appID, tt.pubkey)
			if !assertErr(t, err, tt.wantErr) {
				return
			}

			opts := cmpopts.IgnoreFields(receipt.Receipt{}, "Unknown", "MaxAge")
			if diff := cmp.Diff(tt.want, got, opts); diff != "" {
				t.Errorf("Mismatch (-want +got):\n%s", diff)
			}
		})
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
func mustSelfSignedCert(privKey *ecdsa.PrivateKey) []byte {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		panic(err)
	}

	return certDER
}

func TestReceipt_Unmarshal(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	certDER := mustSelfSignedCert(privKey)

	cases := map[string]struct {
		attributes []receipt.Attribute
		want       *receipt.Receipt
		wantErr    *wantError
	}{
		"AllSupportedFields": {
			attributes: []receipt.Attribute{
				{Type: 2, Raw: mustASN1OctetString([]byte("com.example.app")).Raw},
				{Type: 3, Raw: mustASN1OctetString(certDER).Raw},
				{Type: 6, Raw: mustASN1OctetString([]byte("ATTEST")).Raw},
				{Type: 12, Raw: mustASN1OctetString([]byte(now.Format(time.RFC3339))).Raw},
				{Type: 17, Raw: mustASN1OctetString([]byte("4")).Raw},
				{Type: 19, Raw: mustASN1OctetString([]byte(now.Add(-time.Hour).Format(time.RFC3339))).Raw},
				{Type: 21, Raw: mustASN1OctetString([]byte(now.Add(time.Hour).Format(time.RFC3339))).Raw},
				{Type: 99, Raw: mustASN1OctetString([]byte("unknown")).Raw}, // Unknown
			},
			want: &receipt.Receipt{
				AppID:          "com.example.app",
				PublicKey:      &privKey.PublicKey,
				Type:           "ATTEST",
				CreationTime:   now,
				RiskMetric:     4,
				NotBefore:      now.Add(-time.Hour),
				ExpirationTime: now.Add(time.Hour),
				Unknown: []receipt.Attribute{
					{Type: 99, Raw: mustASN1OctetString([]byte("unknown")).Raw},
				},
			},
		},
		"InvalidCreationTime": {
			attributes: []receipt.Attribute{
				{Type: 12, Raw: mustASN1OctetString([]byte("invalid-time")).Raw},
			},
			wantErr: expectError("failed to unmarshal Creation Time (field:12): parse RFC3339 "),
		},
		"InvalidRiskMetric": {
			attributes: []receipt.Attribute{
				{Type: 17, Raw: mustASN1OctetString([]byte("NaN")).Raw},
			},
			wantErr: expectError("failed to parse RiskMetric string value"),
		},
		"InvalidAppIDEncoding": {
			attributes: []receipt.Attribute{
				{Type: 2, Raw: asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x05}}}, // INTEGER, not OCTET STRING
			},
			wantErr: expectError("failed to unmarshal AppID"),
		},
		"InvalidReceiptTypeEncoding": {
			attributes: []receipt.Attribute{
				{Type: 6, Raw: asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x05}}},
			},
			wantErr: expectError("failed to unmarshal Receipt Type"),
		},
		"InvalidAttestedCertEncoding": {
			attributes: []receipt.Attribute{
				{Type: 3, Raw: asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x05}}},
			},
			wantErr: expectError("failed to unmarshal Attested Public Key"),
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := &receipt.Receipt{}
			err := r.Unmarshal(tc.attributes)
			if !assertErr(t, err, tc.wantErr) {
				return
			}
			if diff := cmp.Diff(tc.want, r); diff != "" {
				t.Errorf("Unmarshal() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func logReceipt(got *receipt.Receipt) string {
	formatPublicKey := func(pubkey *ecdsa.PublicKey) string {
		if pubkey == nil {
			return "<nil>"
		}

		return fmt.Sprintf(
			"Curve=%s X=%064x Y=%064x",
			pubkey.Curve.Params().Name,
			pubkey.X,
			pubkey.Y,
		)
	}

	return fmt.Sprintf(
		"receipt:\n"+
			"  AppID:          %s\n"+
			"  Type:           %s\n"+
			"  CreationTime:   %s\n"+
			"  RiskMetric:     %d\n"+
			"  PublicKey:      %s\n"+
			"  Unknown:        %+v",
		got.AppID,
		got.Type,
		got.CreationTime,
		got.RiskMetric,
		formatPublicKey(got.PublicKey),
		got.Unknown,
	)
}
