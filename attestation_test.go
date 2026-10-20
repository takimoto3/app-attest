package attest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	attest "github.com/takimoto3/app-attest"
	"github.com/takimoto3/app-attest/cbor"
)

var credCertOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

type testChain struct {
	root            *x509.Certificate
	rootDER         []byte
	rootKey         *ecdsa.PrivateKey
	intermediate    *x509.Certificate
	intermediateDER []byte
	intermediateKey *ecdsa.PrivateKey
	credKey         *ecdsa.PrivateKey
}

type certOption func(*x509.Certificate)

func withNotAfter(t time.Time) certOption {
	return func(c *x509.Certificate) { c.NotAfter = t }
}

func withNotBefore(t time.Time) certOption {
	return func(c *x509.Certificate) { c.NotBefore = t }
}

func withoutExtension(oid asn1.ObjectIdentifier) certOption {
	return func(c *x509.Certificate) {
		var kept []pkix.Extension
		for _, e := range c.ExtraExtensions {
			if !e.Id.Equal(oid) {
				kept = append(kept, e)
			}
		}
		c.ExtraExtensions = kept
	}
}

func withCorruptedExtension(oid asn1.ObjectIdentifier, value []byte) certOption {
	return func(c *x509.Certificate) {
		for i, e := range c.ExtraExtensions {
			if e.Id.Equal(oid) {
				c.ExtraExtensions[i].Value = value
			}
		}
	}
}

// aclBlobOID is the OID for the macOS access-control-list extension (1.2.840.113635.100.8.6).
var aclBlobOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 6}

// expectedACLBase64 mirrors the constant used by the production code, so tests
// can build a certificate whose aclBlob matches (or intentionally does not match).
const expectedACLBase64 = "MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB"

// withACLBlob attaches a correctly DER-wrapped aclBlob extension (OCTET STRING inside
// a SEQUENCE) with the given raw blob value.
func withACLBlob(blob []byte) certOption {
	return func(c *x509.Certificate) {
		innerOctet, err := asn1.Marshal(blob)
		if err != nil {
			panic(err)
		}
		wrapped := asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        1,
			IsCompound: true,
			Bytes:      innerOctet,
		}
		seq, err := asn1.Marshal([]asn1.RawValue{wrapped})
		if err != nil {
			panic(err)
		}
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: aclBlobOID, Value: seq})
	}
}

func decodeExpectedACL(t *testing.T) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(expectedACLBase64)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestChain(t testing.TB) *testChain {
	t.Helper()
	now := time.Now()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	// Intermediate CA
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediateDER, err := x509.CreateCertificate(
		rand.Reader,
		&x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: "test intermediate"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		},
		root,
		&intermediateKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}

	credKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return &testChain{
		root:            root,
		rootDER:         rootDER,
		rootKey:         rootKey,
		intermediate:    intermediate,
		intermediateDER: intermediateDER,
		intermediateKey: intermediateKey,
		credKey:         credKey,
	}
}

// replace returns a copy of parts with parts[i] replaced by v.
// The original slice is left untouched, so it can be reused as a base
// template for multiple test cases without risk of mutation leaking
// between them.
func replace(parts [][]byte, i int, v []byte) [][]byte {
	out := make([][]byte, len(parts))
	copy(out, parts)
	out[i] = v
	return out
}

// buildCredCert builds the leaf credential cert with a correct nonce extension
// derived from authData + clientDataHash, unless overridden by opts.
func (tc *testChain) buildCredCert(t testing.TB, authData, clientDataHash []byte, opts ...certOption) []byte {
	t.Helper()
	now := time.Now()

	h := sha256.New()
	h.Write(authData)
	h.Write(clientDataHash)
	nonce := h.Sum(nil)

	// inner: OCTET STRING nonce TLV
	innerOctet, err := asn1.Marshal(nonce)
	if err != nil {
		t.Fatal(err)
	}

	// wrapped: [1] { OCTET STRING nonce } wrapped with context-specific constructed tag
	wrapped := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      innerOctet,
	}

	// seq: SEQUENCE { wrapped }
	seq, err := asn1.Marshal([]asn1.RawValue{wrapped})
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test credential"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: credCertOID, Value: seq},
		},
	}
	for _, opt := range opts {
		opt(tmpl)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tc.intermediate, &tc.credKey.PublicKey, tc.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// buildCredCertWithKey behaves like buildCredCert but signs the credential
// certificate for an arbitrary public key, so tests can exercise credential
// certificates whose key type isn't ECDSA.
func (tc *testChain) buildCredCertWithKey(t testing.TB, pub any, authData, clientDataHash []byte) []byte {
	t.Helper()
	now := time.Now()

	h := sha256.New()
	h.Write(authData)
	h.Write(clientDataHash)
	nonce := h.Sum(nil)

	innerOctet, err := asn1.Marshal(nonce)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      innerOctet,
	}
	seq, err := asn1.Marshal([]asn1.RawValue{wrapped})
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test credential"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: credCertOID, Value: seq},
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tc.intermediate, pub, tc.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestAttestationService_Verify(t *testing.T) {
	chain := newTestChain(t)
	rootCA := x509.NewCertPool()
	rootCA.AddCert(chain.root)

	otherChain := newTestChain(t)
	otherRootCA := x509.NewCertPool()
	otherRootCA.AddCert(otherChain.root)

	const appID = "1234567890.com.example.myapp"
	rpIDHash := sha2(appID)

	challenge := []byte("example_server_challenge")
	clientDataHash := sha256.Sum256(challenge)

	wrongChallenge := []byte("WRONG_example_server_challenge")
	wrongClientDataHash := sha256.Sum256(wrongChallenge)

	pubBytes, err := chain.credKey.PublicKey.Bytes() // X9.62 uncompressed point format
	if err != nil {
		t.Fatal(err)
	}
	keyID := sha256.Sum256(pubBytes)

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPubBytes, err := wrongKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyID := sha256.Sum256(wrongPubBytes)

	// credentialID represents the hash of the public key in the spec, so use the same value as keyID
	credentialID := keyID[:]

	// --- Success Cases ---
	extensions := cborMap(
		item{cborText("apple_bundle_version_01"), cborText("1.0")},
		item{cborText("apple_validation_category_01"), []byte{0x44, 0x01, 0x00, 0x00, 0x00}},
	)
	cosekey := cborMap( // COSE Key
		item{cborUint(1), cborUint(2)},
		item{cborUint(3), cborNegInt(-7)},
		item{cborNegInt(-1), cborUint(1)},
		item{cborNegInt(-2), cborBytes(chain.credKey.PublicKey.X.FillBytes(make([]byte, 32)))},
		item{cborNegInt(-3), cborBytes(chain.credKey.PublicKey.Y.FillBytes(make([]byte, 32)))},
	)

	// production: aaguid = "appattest" + 7 x 0x00
	authDataParts := [][]byte{
		rpIDHash,
		[]byte{0x40},
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]byte("appattest\x00\x00\x00\x00\x00\x00\x00"),
		binary.BigEndian.AppendUint16(nil, uint16(len(credentialID))),
		credentialID,
	}

	noExtensionsAuthData := merge(append(authDataParts, cosekey)...)

	authDataParts = append(append(authDataParts, cosekey), extensions)
	productionAuthData := merge(authDataParts...)

	// development: aaguid = "appattestdevelop"
	developmentAuthData := merge(replace(authDataParts, 3, []byte("appattestdevelop"))...)
	// development: aaguid = "appattestsandbox"
	sandboxAuthData := merge(replace(authDataParts, 3, []byte("appattestsandbox"))...)

	// --- Error Cases ---

	// #18: authData is too short and fails to unmarshal
	shortAuthData := productionAuthData[:10]

	// #19: attested credential data flag is not set
	noAttestedFlagAuthData := merge(
		rpIDHash,
		[]byte{0x00}, // flag: no attested credential
		[]byte{0x00, 0x00, 0x00, 0x00},
	)

	// #21: counter is not zero
	counterNonZeroAuthData := merge(replace(authDataParts, 2, []byte{0x00, 0x00, 0x00, 0x01})...)

	// #22: aaguid is neither production nor development
	invalidAaguidAuthData := merge(replace(authDataParts, 3, []byte("invalid-aaguid\x00\x00"))...)

	// #23: credentialID does not match keyID
	mismatchedCredentialID := []byte("different-credential-id-32bytes\x00")
	credMismatchAuthData := merge(replace(authDataParts, 5, mismatchedCredentialID)...)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		rootCA         *x509.CertPool
		identifier     string
		attestObject   *attest.AttestationObject
		clientDataHash []byte
		keyID          []byte
		want           *attest.Result
		wantErr        *wantError
	}{
		"success (production)": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, productionAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			want: &attest.Result{
				Environment:             attest.Production,
				Receipt:                 []byte("dummy-receipt-bytes"),
				PublicKey:               &chain.credKey.PublicKey,
				AppleBundleVersion:      "1.0",
				AppleValidationCategory: 1,
			},
		},
		"success (development: appattestdevelop)": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: developmentAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, developmentAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			want: &attest.Result{
				Environment:             attest.Development,
				Receipt:                 []byte("dummy-receipt-bytes"),
				PublicKey:               &chain.credKey.PublicKey,
				AppleBundleVersion:      "1.0",
				AppleValidationCategory: 1,
			},
		},
		"success (development: appattestsandbox)": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: sandboxAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, sandboxAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			want: &attest.Result{
				Environment:             attest.Development,
				Receipt:                 []byte("dummy-receipt-bytes"),
				PublicKey:               &chain.credKey.PublicKey,
				AppleBundleVersion:      "1.0",
				AppleValidationCategory: 1,
			},
		},
		"attestObject is nil": {
			rootCA:         rootCA,
			identifier:     appID,
			attestObject:   nil,
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("attestObj is nil"),
		},
		"RootCertPool is nil": {
			identifier: appID,
			attestObject: &attest.AttestationObject{
				Format: "packed",
				AttStmt: attest.AttStmt{
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("root certificate pool is nil"),
		},
		"invalid format": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				Format: "packed",
				AttStmt: attest.AttStmt{
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError(`invalid attestation format: "packed"`),
		},
		"AuthData is empty": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: nil,
				Format:   "apple-appattest",
				AttStmt:  attest.AttStmt{},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("authData: empty data"),
		},
		"AttStmt has no data": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt:  attest.AttStmt{},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("AttStmt: empty data"),
		},
		"x5c chain too short": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, productionAuthData, clientDataHash[:])}, // only 1 entry
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("x5c chain must contain credential and intermediate certificates"),
		},
		"credential cert malformed DER": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{[]byte("not a certificate"), chain.rootDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("parsing certificate from ASN.1 data failed"),
		},
		"intermediate cert malformed DER": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, productionAuthData, clientDataHash[:]), []byte("not a certificate")},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("parsing intermediate certificate at index 1 failed"),
		},
		"certificate expired": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C: [][]byte{chain.buildCredCert(t, productionAuthData, clientDataHash[:],
						withNotAfter(time.Now().Add(-time.Hour))), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("expired"),
		},
		"missing credCert extension": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C: [][]byte{chain.buildCredCert(t, productionAuthData, clientDataHash[:],
						withoutExtension(credCertOID)), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("certificate didn't contain credCert extension"),
		},
		"wrong client data hash (nonce mismatch)": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, productionAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: wrongClientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("credCert extension does not match nonce"),
		},
		"wrong keyID": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, productionAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          wrongKeyID[:],
			wantErr:        expectError("the keyid is not match public key's hash"),
		},
		"authData too short": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: shortAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, shortAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("authenticator data decoding failed"),
		},
		"missing attested credential data flag": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: noAttestedFlagAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, noAttestedFlagAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("authenticator data decoding failed: failed to read AAGUID: unexpected EOF"),
		},
		"wrong appID (RPIDHash mismatch)": {
			rootCA:     rootCA,
			identifier: "OTHER.com.example.app",
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, productionAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError(attest.ErrUnmatchRPIDHash),
		},
		"counter not zero": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: counterNonZeroAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, counterNonZeroAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("authenticator data counter was not 0"),
		},
		"invalid aaguid": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: invalidAaguidAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, invalidAaguidAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("invalid aaguid value"),
		},
		"credential ID mismatch": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: credMismatchAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, credMismatchAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("credential ID did not equal the provided key identifier"),
		},
		"corrupted credCert extension (invalid ASN.1)": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C: [][]byte{chain.buildCredCert(t, productionAuthData, clientDataHash[:],
						withCorruptedExtension(credCertOID, []byte{0xFF, 0xFF})), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("credCert extension parse error"),
		},
		"certificate not yet valid": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C: [][]byte{chain.buildCredCert(t, productionAuthData, clientDataHash[:],
						withNotBefore(time.Now().Add(time.Hour))), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("expired or is not yet valid"),
		},
		"untrusted root (different CA)": {
			rootCA:     otherRootCA, // chain is valid, but the trusted root is a different CA
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, productionAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("unknown authority"),
		},
		"intermediate certificate missing": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, productionAuthData, clientDataHash[:]), chain.rootDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("unknown authority"),
		},
		"missing extensions (no apple_bundle_version_01 / apple_validation_category_01)": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: noExtensionsAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, noExtensionsAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			want: &attest.Result{
				Environment:             attest.Production,
				Receipt:                 []byte("dummy-receipt-bytes"),
				PublicKey:               &chain.credKey.PublicKey,
				AppleBundleVersion:      "",
				AppleValidationCategory: 0,
			},
		},
		"credential cert uses non-ECDSA key": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: productionAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCertWithKey(t, &rsaKey.PublicKey, productionAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: clientDataHash[:],
			keyID:          keyID[:],
			wantErr:        expectError("invalid key algorithm"),
		},
		"empty clientDataHash": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: developmentAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, developmentAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: []byte{},
			keyID:          keyID[:],
			wantErr:        expectError("credCert extension does not match nonce"),
		},
		"short clientDataHash": {
			rootCA:     rootCA,
			identifier: appID,
			attestObject: &attest.AttestationObject{
				AuthData: developmentAuthData,
				Format:   "apple-appattest",
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{chain.buildCredCert(t, developmentAuthData, clientDataHash[:]), chain.intermediateDER},
					Receipt: []byte("dummy-receipt-bytes"),
				},
			},
			clientDataHash: make([]byte, 31),
			keyID:          keyID[:],
			wantErr:        expectError("credCert extension does not match nonce"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Run("VerifyForiOS", func(t *testing.T) {
				target := attest.AttestationService{RootCertPool: tt.rootCA}

				result, err := target.VerifyForiOS(tt.attestObject, tt.identifier, tt.clientDataHash, tt.keyID)
				if !assertErr(t, err, tt.wantErr) {
					return
				}

				if diff := cmp.Diff(tt.want, result); diff != "" {
					t.Errorf("Verify() mismatch (-want +got):\n%s", diff)
				}
			})
			t.Run("Verify", func(t *testing.T) {
				target := attest.NewAttestationService(tt.rootCA, tt.identifier)

				result, err := target.Verify(tt.attestObject, tt.clientDataHash, tt.keyID)
				if !assertErr(t, err, tt.wantErr) {
					return
				}

				if diff := cmp.Diff(tt.want, result); diff != "" {
					t.Errorf("Verify() mismatch (-want +got):\n%s", diff)
				}
			})
		})
	}
}

func TestAttestationObject_UnmarshalCBOR(t *testing.T) {
	tests := map[string]struct {
		data    []byte
		want    *attest.AttestationObject
		wantErr *wantError
	}{
		"valid: fmt, authData, attStmt with x5c and receipt": {
			data: cborMap(
				item{cborText("fmt"), cborText("apple-appattest")},
				item{cborText("authData"), cborBytes([]byte("auth-data-bytes"))},
				item{cborText("attStmt"), cborMap(
					item{cborText("x5c"), merge(
						[]byte{0x80 | 2}, // CBOR array header: major type 4 (array), 2 items
						cborBytes([]byte("leaf-cert-der")),
						cborBytes([]byte("intermediate-cert-der")),
					)},
					item{cborText("receipt"), cborBytes([]byte("receipt-bytes"))},
				)},
			),
			want: &attest.AttestationObject{
				Format:   "apple-appattest",
				AuthData: []byte("auth-data-bytes"),
				AttStmt: attest.AttStmt{
					X5C:     [][]byte{[]byte("leaf-cert-der"), []byte("intermediate-cert-der")},
					Receipt: []byte("receipt-bytes"),
				},
			},
		},
		"empty data": {
			data:    []byte{},
			wantErr: expectError(io.ErrUnexpectedEOF),
		},
		"not a map": {
			data:    cborUint(1),
			wantErr: expectError(fmt.Sprintf("expected CBOR type Map (major type 5) for AttestationObject, got major type %d", cbor.UnsignedInt)),
		},
		"map key not text": {
			data: cborMap(
				item{cborUint(1), cborText("apple-appattest")},
			),
			wantErr: expectError(fmt.Sprintf("expected string map key at index %d, got major type %d", 0, cbor.UnsignedInt)),
		},
		"fmt wrong value type": {
			data: cborMap(
				item{cborText("fmt"), cborUint(1)},
			),
			wantErr: expectError(fmt.Sprintf(`expected string for format (key "fmt"), got major type %d`, cbor.UnsignedInt)),
		},
		"authData wrong value type": {
			data: cborMap(
				item{cborText("authData"), cborText("not-bytes")},
			),
			wantErr: expectError(fmt.Sprintf(`expected bytestring for authData (key "authData"), got major type %d`, cbor.TextString)),
		},
		"attStmt not a map": {
			data: cborMap(
				item{cborText("attStmt"), cborUint(1)},
			),
			wantErr: expectError(fmt.Sprintf(`failed to unmarshal attStmt (key "attStmt"): expected CBOR type Map (major type 5) for attStmt, got major type %d`, cbor.UnsignedInt)),
		},
		"unknown top-level key": {
			data: cborMap(
				item{cborText("unknown"), cborUint(1)},
			),
			wantErr: expectError(attest.ErrUnknownKey),
		},
		"unknown key with unsupported nested map fails": {
			data: cborMap(
				item{cborText("unknown"), cborMap(item{cborUint(1), cborUint(2)})}, // unknown key with nested map value
			),
			wantErr: expectError(attest.ErrUnknownKey),
		},
		"missing authData and attStmt": {
			data:    cborMap(item{cborText("fmt"), cborText("apple-appattest")}),
			wantErr: expectError(attest.ErrMissingKey),
		},
		"missing fmt and attStmt": {
			data:    cborMap(item{cborText("authData"), cborBytes([]byte("auth-data-bytes"))}),
			wantErr: expectError(attest.ErrMissingKey),
		},
		"missing fmt and authData": {
			data: cborMap(
				item{cborText("attStmt"), cborMap(
					item{cborText("x5c"), []byte{0x80}},
					item{cborText("receipt"), cborBytes([]byte("r"))},
				)},
			),
			wantErr: expectError(attest.ErrMissingKey),
		},
		"missing attStmt": {
			data: cborMap(
				item{cborText("fmt"), cborText("apple-appattest")},
				item{cborText("authData"), cborBytes([]byte("auth-data-bytes"))},
			),
			wantErr: expectError(attest.ErrMissingKey),
		},
		"empty map": {
			data:    []byte{0xA0},
			wantErr: expectError(attest.ErrMissingKey),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var ao attest.AttestationObject
			err := ao.UnmarshalCBOR(tt.data)
			if !assertErr(t, err, tt.wantErr) {
				return
			}

			if diff := cmp.Diff(tt.want, &ao); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAttStmt_UnmarshalCBOR(t *testing.T) {
	tests := map[string]struct {
		data    []byte
		want    *attest.AttStmt
		wantErr *wantError
	}{
		"valid: x5c with two certs and receipt": {
			data: cborMap(
				item{cborText("x5c"), merge(
					[]byte{0x80 | 2}, // CBOR array header: major type 4 (array), 2 items
					cborBytes([]byte("leaf-cert-der")),
					cborBytes([]byte("intermediate-cert-der")),
				)},
				item{cborText("receipt"), cborBytes([]byte("receipt-bytes"))},
			),
			want: &attest.AttStmt{
				X5C:     [][]byte{[]byte("leaf-cert-der"), []byte("intermediate-cert-der")},
				Receipt: []byte("receipt-bytes"),
			},
		},
		"empty data": {
			data:    []byte{},
			wantErr: expectError(io.ErrUnexpectedEOF),
		},
		"not a map": {
			data:    cborUint(1),
			wantErr: expectError(fmt.Sprintf("expected CBOR type Map (major type 5) for attStmt, got major type %d", cbor.UnsignedInt)),
		},
		"map key not text": {
			data: cborMap(
				item{cborUint(1), cborBytes([]byte("x"))},
			),
			wantErr: expectError(fmt.Sprintf("expected string map key at index %d, got major type %d", 0, cbor.UnsignedInt)),
		},
		"receipt wrong value type": {
			data: cborMap(
				item{cborText("receipt"), cborUint(1)},
			),
			wantErr: expectError(fmt.Sprintf(`expected bytestring for receipt (key "receipt"), got major type %d`, cbor.UnsignedInt)),
		},
		"x5c not an array": {
			data: cborMap(
				item{cborText("x5c"), cborUint(1)},
			),
			wantErr: expectError(fmt.Sprintf(`expected array for x5c (key "x5c"), got major type %d`, cbor.UnsignedInt)),
		},
		"x5c array item wrong type": {
			data: cborMap(
				item{cborText("x5c"), merge(
					[]byte{0x80 | 1}, // CBOR array header: major type 4 (array), 1 item
					cborText("not-bytes"),
				)},
			),
			wantErr: expectError(fmt.Sprintf("expected bytestring in x5c array at index %d, got major type %d", 0, cbor.TextString)),
		},
		"x5c empty array": {
			data: cborMap(
				item{cborText("x5c"), []byte{0x80}}, // CBOR array header: major type 4, 0 items
				item{cborText("receipt"), cborBytes([]byte("receipt-bytes"))},
			),
			want: &attest.AttStmt{
				X5C:     [][]byte{},
				Receipt: []byte("receipt-bytes"),
			},
		},
		"unknown key": {
			data: cborMap(
				item{cborText("unknown"), cborUint(1)},
			),
			wantErr: expectError(attest.ErrUnknownKey),
		},
		"unknown key with unsupported nested map fails": {
			data: cborMap(
				item{cborText("unknown"), cborMap(item{cborUint(1), cborUint(2)})}, // unknown key with nested map value
			),
			wantErr: expectError(attest.ErrUnknownKey),
		},
		"x5c array exceeds maximum certificate count": {
			data: cborMap(
				item{
					cborText("x5c"),
					[]byte{0x89}, // CBOR array(9)
				},
			),
			wantErr: expectError(fmt.Sprintf(`x5c array too large (key "x5c"): got %d, max %d`, 9, 8)),
		},
		"duplicate receipt key": {
			data: cborMap(
				item{cborText("receipt"), cborBytes([]byte("a"))},
				item{cborText("receipt"), cborBytes([]byte("b"))},
			),
			wantErr: expectError(attest.ErrDuplicateKey),
		},
		"duplicate x5c key": {
			data: cborMap(
				item{cborText("x5c"), []byte{0x80}},
				item{cborText("x5c"), []byte{0x80}},
			),
			wantErr: expectError(attest.ErrDuplicateKey),
		},
		"missing receipt": {
			data:    cborMap(item{cborText("x5c"), []byte{0x80}}),
			wantErr: expectError(attest.ErrMissingKey),
		},
		"missing x5c": {
			data:    cborMap(item{cborText("receipt"), cborBytes([]byte("r"))}),
			wantErr: expectError(attest.ErrMissingKey),
		},
		"empty map": {
			data:    []byte{0xA0},
			wantErr: expectError(attest.ErrMissingKey),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dec := cbor.NewDecoder(tt.data)
			as := &attest.AttStmt{}
			err := as.UnmarshalCBOR(dec)
			if !assertErr(t, err, tt.wantErr) {
				return
			}

			if diff := cmp.Diff(tt.want, as); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func BenchmarkAttestationObject_UnmarshalCBOR(b *testing.B) {
	chain := newTestChain(b)

	const appID = "1234567890.com.example.myapp"
	rpIDHash := sha2(appID)

	challenge := []byte("example_server_challenge")
	clientDataHash := sha256.Sum256(challenge)

	pubBytes, err := chain.credKey.PublicKey.Bytes()
	if err != nil {
		b.Fatal(err)
	}
	keyID := sha256.Sum256(pubBytes)
	credentialID := keyID[:]

	authData := merge(
		rpIDHash,
		[]byte{0x40},
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]byte("appattest\x00\x00\x00\x00\x00\x00\x00"),
		binary.BigEndian.AppendUint16(nil, uint16(len(credentialID))),
		credentialID,
		cborMap( // COSE Key
			item{cborUint(1), cborUint(2)},
			item{cborUint(3), cborNegInt(-7)},
			item{cborNegInt(-1), cborUint(1)},
			item{cborNegInt(-2), cborBytes(chain.credKey.PublicKey.X.FillBytes(make([]byte, 32)))},
			item{cborNegInt(-3), cborBytes(chain.credKey.PublicKey.Y.FillBytes(make([]byte, 32)))},
		),
		cborMap( // Extensions
			item{cborText("apple_bundle_version_01"), cborText("1.0")},
			item{cborText("apple_validation_category_01"), []byte{0x44, 0x01, 0x00, 0x00, 0x00}},
		),
	)

	credCertDER := chain.buildCredCert(b, authData, clientDataHash[:])

	data := cborMap(
		item{cborText("fmt"), cborText("apple-appattest")},
		item{cborText("authData"), cborBytes(authData)},
		item{cborText("attStmt"), cborMap(
			item{cborText("x5c"), merge(
				[]byte{0x80 | 2}, // CBOR array header: major type 4 (array), 2 items
				cborBytes(credCertDER),
				cborBytes(chain.rootDER),
			)},
			item{cborText("receipt"), cborBytes([]byte("dummy-receipt-bytes"))},
		)},
	)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var ao attest.AttestationObject
		if err := ao.UnmarshalCBOR(data); err != nil {
			b.Fatal(err)
		}
	}
}
