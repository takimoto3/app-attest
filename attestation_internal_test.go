package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestExpectedACL(t *testing.T) {
	const expectedACLBase64 = "MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB"
	want, err := base64.StdEncoding.DecodeString(expectedACLBase64)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, expectedACL); diff != "" {
		t.Errorf("expectedACL mismatch (-want +got):\n%s", diff)
	}
}

func TestVerifyCredentialCertificateAcceptsNonTLSExtendedKeyUsage(t *testing.T) {
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "App Attest test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	credentialKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credentialTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "App Attest credential"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		// A non-TLS EKU reproduces the failure caused by crypto/x509's implicit
		// ServerAuth default while still allowing the pinned-chain check we need.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	credentialDER, err := x509.CreateCertificate(rand.Reader, credentialTemplate, root, &credentialKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := x509.ParseCertificate(credentialDER)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	if err := verifyCredentialCertificate(credential, roots, x509.NewCertPool()); err != nil {
		t.Fatalf("valid non-TLS App Attest credential chain was rejected: %v", err)
	}
}

func TestSafeReader_ReadBytes(t *testing.T) {
	r := safeReader{rawBytes: []byte{1, 2, 3}}

	if _, err := r.ReadBytes(-1); err == nil {
		t.Error("ReadBytes(-1): expected error")
	}
	if _, err := r.ReadBytes(4); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("ReadBytes(4): got %v, want io.ErrUnexpectedEOF", err)
	}
	if r.Len() != 3 {
		t.Errorf("failed reads must not advance: Len() = %d, want 3", r.Len())
	}
	b, err := r.ReadBytes(3)
	if err != nil || len(b) != 3 {
		t.Fatalf("ReadBytes(3) = %v, %v", b, err)
	}
	if _, err := r.ReadByte(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("ReadByte at end: got %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestSafeReader_ReadUint(t *testing.T) {
	r := safeReader{rawBytes: []byte{0x01, 0x02, 0x03}}
	if _, err := r.ReadUint32(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("ReadUint32 on 3 bytes: got %v", err)
	}
	v, err := r.ReadUint16()
	if err != nil || v != 0x0102 {
		t.Errorf("ReadUint16 = %#x, %v; want 0x0102 (big endian)", v, err)
	}
	if _, err := r.ReadUint16(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("ReadUint16 on 1 byte: got %v", err)
	}
}

func TestSafeReader_AdvanceAndUnread(t *testing.T) {
	r := safeReader{rawBytes: []byte{1, 2, 3}}

	r.Advance(-5) // negative is treated as 0
	if r.Len() != 3 {
		t.Errorf("Advance(-5): Len() = %d, want 3", r.Len())
	}
	r.Advance(1)
	if got := r.UnreadBytes(); len(got) != 2 || got[0] != 2 {
		t.Errorf("UnreadBytes = %v, want [2 3]", got)
	}
	r.Advance(100) // clamped to the end
	if r.Len() != 0 {
		t.Errorf("Advance(100): Len() = %d, want 0", r.Len())
	}
	if got := r.UnreadBytes(); got != nil {
		t.Errorf("UnreadBytes at end = %v, want nil", got)
	}
}
