package attest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"
	attest "github.com/takimoto3/app-attest"
	"github.com/takimoto3/app-attest/cbor"
)

// TestAuthenticatorData_Unmarshal_AppleGuideExtensions verifies that
// Unmarshal correctly decodes the iOS 27+ extensions
// (apple_bundle_version_01 / apple_validation_category_01) from real
// Apple-signed authData, using parseAppleGuide to decode it via the
// package's own CBOR path (AttestationObject.UnmarshalCBOR).
func TestAuthenticatorData_Unmarshal_AppleGuideExtensions(t *testing.T) {
	rpIDHash := sha256.Sum256([]byte("1234567890.com.example.myapp"))
	want := attest.AuthenticatorData{
		RPIDHash: rpIDHash[:],
		Flags:    0x40,
		Counter:  0,
		CredentialData: attest.AttestedCredential{
			AAGUID: []byte("appattest\x00\x00\x00\x00\x00\x00\x00"),
			CredentialID: []byte{
				0xce, 0x04, 0x98, 0xf5, 0x84, 0x83, 0xfb, 0xb4,
				0xda, 0x0d, 0x7b, 0x2c, 0x63, 0xa5, 0xa5, 0x38,
				0xf5, 0x52, 0xd4, 0xad, 0xcb, 0x9a, 0x4f, 0xa9,
				0x16, 0x19, 0x5c, 0x49, 0x61, 0x3e, 0x65, 0x5d,
			},
			CoseKey: attest.CoseKey{
				Kty: 2,  // EC2
				Alg: -7, // ES256
				Crv: 1,  // P-256
				X: []byte{
					0x43, 0x32, 0x54, 0x4a, 0xcf, 0x32, 0x3d, 0xb7,
					0x74, 0x44, 0x3c, 0xaa, 0xf3, 0x39, 0xf5, 0x6e,
					0x7e, 0x95, 0xc7, 0x24, 0xfa, 0xc2, 0xc1, 0x42,
					0x59, 0xf3, 0x65, 0xe2, 0x44, 0x56, 0x50, 0xb2,
				},
				Y: []byte{
					0xb5, 0xfb, 0x28, 0x5b, 0xcf, 0x54, 0x9b, 0xcb,
					0x60, 0x59, 0x44, 0x12, 0xe7, 0x68, 0x2a, 0x24,
					0x27, 0xee, 0xad, 0xa9, 0xfb, 0x52, 0xdf, 0xed,
					0x0b, 0x1a, 0xb1, 0x7e, 0xd0, 0x9f, 0xa9, 0xbd,
				},
			},
		},
		AppleBundleVersion:      "1",
		AppleValidationCategory: 1,
	}
	attestObj := parseAppleGuide(t)
	authData := attest.AuthenticatorData{}
	if err := authData.Unmarshal(attestObj.AuthData, true); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, authData); diff != "" {
		t.Errorf("ParseAuthenticatorData mismatch (-want +got):\n%s", diff)
	}
}

func TestCoseKey_Unmarshal(t *testing.T) {
	x, ok := new(big.Int).SetString("7edc0361ca4374f1969d8258f59f5df858d2f5c16a4d3329a6c79798455981b4", 16)
	if !ok {
		t.Fatal("invalid X hex")
	}
	y, ok := new(big.Int).SetString("16faa25765c3ffb95fc545cdd05c75361253f0d2456227f341da652721bf05e3", 16)
	if !ok {
		t.Fatal("invalid Y hex")
	}
	publicKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if _, err := publicKey.ECDH(); err != nil {
		t.Fatalf("fixed key is not a valid P-256 point: %v", err)
	}

	tests := map[string]struct {
		data    []byte
		wantKey *ecdsa.PublicKey
		wantErr *wantError
	}{
		"valid cose key": {
			data: cborMap( // Cose Key
				item{cborUint(1), cborUint(2)},                       // ktv: EC2
				item{cborUint(3), cborNegInt(-7)},                    // alg: ES256
				item{cborNegInt(-1), cborUint(1)},                    // crv: P-256
				item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())}, // X
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())}, // Y
			),
			wantKey: publicKey,
		},
		"empty bytes": {
			data:    []byte{},
			wantErr: expectError("failed to read CBOR map header", io.ErrUnexpectedEOF)},
		"map key not integer": {
			data: cborMap( // Cose Key
				item{cborText("1"), cborUint(2)},                     // ktv: EC2
				item{cborUint(3), cborNegInt(-7)},                    // alg: ES256
				item{cborNegInt(-1), cborUint(1)},                    // crv: P-256
				item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())}, // X
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())}, // Y
			),
			wantErr: expectError(fmt.Sprintf("expected integer map key at index %d, got major type %d", 0, cbor.TextString)),
		},
		"invalid key": {
			data: cborMap( // Cose Key
				item{cborUint(9), cborUint(2)},                       // ktv: EC2
				item{cborUint(3), cborNegInt(-7)},                    // alg: ES256
				item{cborNegInt(-1), cborUint(1)},                    // crv: P-256
				item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())}, // X
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())}, // Y
			),
			wantErr: expectError("unknown key: 9", attest.ErrUnknownKey),
		},
		"truncated map": {
			data: []byte{
				0xa5, // map(5) — but only 1 entry follows
				0x01, 0x02,
			},
			wantErr: expectError("failed to read map key header at index 1", io.ErrUnexpectedEOF),
		},
		"wrong type for byte string value": {
			data: cborMap(
				item{cborUint(1), cborUint(2)},
				item{cborUint(3), cborNegInt(-7)},
				item{cborNegInt(-1), cborUint(1)},
				item{cborNegInt(-2), cborUint(123)}, // X should be bytes, not uint
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())},
			),
			wantErr: expectError("expected ByteString for X coordinate"),
		},
		"wrong type for Kty": {
			data: cborMap(
				item{cborUint(1), cborText("2")}, // Kty should be int, not text
				item{cborUint(3), cborNegInt(-7)},
				item{cborNegInt(-1), cborUint(1)},
				item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())},
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())},
			),
			wantErr: expectError("expected integer for Kty"),
		},
		"wrong type for Alg": {
			data: cborMap(
				item{cborUint(1), cborUint(2)},
				item{cborUint(3), cborText("-7")}, // Alg should be int, not text
				item{cborNegInt(-1), cborUint(1)},
				item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())},
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())},
			),
			wantErr: expectError("expected integer for Alg"),
		},
		"wrong type for Crv": {
			data: cborMap(
				item{cborUint(1), cborUint(2)},
				item{cborUint(3), cborNegInt(-7)},
				item{cborNegInt(-1), cborText("1")}, // Crv should be int, not text
				item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())},
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())},
			),
			wantErr: expectError("expected integer for Crv"),
		},
		"wrong type for Y": {
			data: cborMap(
				item{cborUint(1), cborUint(2)},
				item{cborUint(3), cborNegInt(-7)},
				item{cborNegInt(-1), cborUint(1)},
				item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())},
				item{cborNegInt(-3), cborUint(123)}, // Y should be bytes, not uint
			),
			wantErr: expectError("expected ByteString for Y coordinate"),
		},
		"truncated after Kty key": {
			data: []byte{
				0xa1, // map(1)
				0x01, // key 1 (Kty), but no value follows
			},
			wantErr: expectError("failed to read Kty header", io.ErrUnexpectedEOF),
		},
		"X byte string length exceeds data": {
			data: []byte{
				0xa1,       // map(1)
				0x21,       // key -2 (X)
				0x58, 0x20, // byte string, 32 bytes declared
				0x01, 0x02, // only 2 bytes follow
			},
			wantErr: expectError("failed to read X coordinate bytes", io.ErrUnexpectedEOF),
		},
		"missing key: x": {
			data: cborMap(
				item{cborUint(1), cborUint(2)},
				item{cborUint(3), cborNegInt(-7)},
				item{cborNegInt(-1), cborUint(1)},
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())},
			),
			wantErr: expectError("x(-2)", attest.ErrMissingKey),
		},
		"empty map": {
			data:    []byte{0xa0},
			wantErr: expectError("kty(1), alg(3), crv(-1), x(-2), y(-3)", attest.ErrMissingKey),
		},
		"duplicate key: kty": {
			data: cborMap(
				item{cborUint(1), cborUint(2)},
				item{cborUint(1), cborUint(2)},
			),
			wantErr: expectError(": 1", attest.ErrDuplicateKey),
		},
		"duplicate key: alg": {
			data: cborMap(
				item{cborUint(3), cborNegInt(-7)},
				item{cborUint(3), cborNegInt(-7)},
			),
			wantErr: expectError(": 3", attest.ErrDuplicateKey),
		},
		"duplicate key: crv": {
			data: cborMap(
				item{cborNegInt(-1), cborUint(1)},
				item{cborNegInt(-1), cborUint(1)},
			),
			wantErr: expectError(": -1", attest.ErrDuplicateKey),
		},
		"duplicate key: x": {
			data: cborMap(
				item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())},
				item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())},
			),
			wantErr: expectError(": -2", attest.ErrDuplicateKey),
		},
		"duplicate key: y": {
			data: cborMap(
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())},
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())},
			),
			wantErr: expectError(": -3", attest.ErrDuplicateKey),
		},
		"duplicate key: different value": {
			data: cborMap(
				item{cborUint(1), cborUint(2)},
				item{cborUint(1), cborUint(9)},
			),
			wantErr: expectError(": 1", attest.ErrDuplicateKey),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var coseKey attest.CoseKey
			dec := cbor.NewDecoder(tt.data)
			err := coseKey.UnmarshalCBOR(dec)
			if !assertErr(t, err, tt.wantErr) {
				return
			}

			if tt.wantKey != nil {
				parsedKey, err := coseKey.ParsePublicKey()
				if err != nil {
					t.Fatal(err)
				}
				if !tt.wantKey.Equal(parsedKey) {
					t.Errorf("ParsePublicKey() mismatch\ngot  (X: %x, Y: %x)\nwant (X: %x, Y: %x)",
						parsedKey.X, parsedKey.Y,
						tt.wantKey.X, tt.wantKey.Y,
					)
				}
			}
		})
	}
}

func TestCoseKey_ParsePublicKey_InvalidLength(t *testing.T) {
	tests := map[string]struct {
		x, y []byte
	}{
		"short X":    {x: make([]byte, 31), y: make([]byte, 32)},
		"short Y":    {x: make([]byte, 32), y: make([]byte, 31)},
		"long X":     {x: make([]byte, 33), y: make([]byte, 32)},
		"long Y":     {x: make([]byte, 32), y: make([]byte, 33)},
		"both short": {x: make([]byte, 31), y: make([]byte, 31)},
		"empty":      {x: nil, y: nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			k := &attest.CoseKey{X: tt.x, Y: tt.y}
			_, err := k.ParsePublicKey()
			assertErr(t, err, expectError("invalid coordinate length"))
		})
	}
}

func TestCoseKey_ParsePublicKey_NotOnCurve(t *testing.T) {
	tests := map[string]struct {
		x, y []byte
	}{
		"all zero": {x: make([]byte, 32), y: make([]byte, 32)},
		"all 0xFF": {x: bytes.Repeat([]byte{0xFF}, 32), y: bytes.Repeat([]byte{0xFF}, 32)},
		"x=1, y=1": {x: append(make([]byte, 31), 1), y: append(make([]byte, 31), 1)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			k := &attest.CoseKey{X: tt.x, Y: tt.y}
			_, err := k.ParsePublicKey()
			assertErr(t, err, expectError("failed to parse uncompressed EC public key"))
		})
	}
}

func TestAuthenticatorData_Unmarshal(t *testing.T) {
	publicKey := generatePublicKey(t)

	rawCredentialID := []byte{
		0xce, 0x04, 0x98, 0xf5, 0x84, 0x83, 0xfb, 0xb4,
		0xda, 0x0d, 0x7b, 0x2c, 0x63, 0xa5, 0xa5, 0x38,
		0xf5, 0x52, 0xd4, 0xad, 0xcb, 0x9a, 0x4f, 0xa9,
		0x16, 0x19, 0x5c, 0x49, 0x61, 0x3e, 0x65, 0xd1,
	}

	tests := map[string]struct {
		data        []byte
		requireCred bool
		want        *attest.AuthenticatorData
		wantErr     *wantError
	}{
		"valid authenticator data": {
			data: merge(
				sha2("1234567890.appleID"),                                       // RP ID hash
				[]byte{0x40},                                                     // flag
				[]byte{0x00, 0x00, 0x00, 0x00},                                   // counter
				[]byte("appattest\x00\x00\x00\x00\x00\x00\x00"),                  // aaguid
				binary.BigEndian.AppendUint16(nil, uint16(len(rawCredentialID))), // CredID Len
				rawCredentialID,                                                  // CredID
				cborMap( // Cose Key
					item{cborUint(1), cborUint(2)},                       // ktv: EC2
					item{cborUint(3), cborNegInt(-7)},                    // alg: ES256
					item{cborNegInt(-1), cborUint(1)},                    // crv: P-256
					item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())}, // X
					item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())}, // Y
				),
				cborMap( // Extensions
					item{cborText("apple_validation_category_01"), cborBytes([]byte{0x01, 0x00, 0x00, 0x00})}, // apple_validation_category_01
					item{cborText("apple_bundle_version_01"), cborText("1.0")},                                // apple_bundle_version_01
				),
			),
			requireCred: true,
			want: &attest.AuthenticatorData{
				RPIDHash: sha2("1234567890.appleID"),
				Flags:    0x40,
				Counter:  0,
				CredentialData: attest.AttestedCredential{
					AAGUID:       []byte("appattest\x00\x00\x00\x00\x00\x00\x00"),
					CredentialID: rawCredentialID,
					CoseKey: attest.CoseKey{
						Kty: 2,
						Alg: -7,
						Crv: 1,
						X:   publicKey.X.Bytes(),
						Y:   publicKey.Y.Bytes(),
					},
				},
				AppleValidationCategory: 1,
				AppleBundleVersion:      "1.0",
			},
		},
		"valid: attested credential present, no extensions": {
			data: merge(
				sha2("1234567890.appleID"),                                       // RP ID hash
				[]byte{0x40},                                                     // flag
				[]byte{0x00, 0x00, 0x00, 0x00},                                   // counter
				[]byte("appattest\x00\x00\x00\x00\x00\x00\x00"),                  // aaguid
				binary.BigEndian.AppendUint16(nil, uint16(len(rawCredentialID))), // CredID Len
				rawCredentialID,                                                  // CredID
				cborMap( // Cose Key
					item{cborUint(1), cborUint(2)},                       // ktv: EC2
					item{cborUint(3), cborNegInt(-7)},                    // alg: ES256
					item{cborNegInt(-1), cborUint(1)},                    // crv: P-256
					item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())}, // X
					item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())}, // Y
				),
			),
			requireCred: true,
			want: &attest.AuthenticatorData{
				RPIDHash: sha2("1234567890.appleID"),
				Flags:    0x40,
				Counter:  0,
				CredentialData: attest.AttestedCredential{
					AAGUID:       []byte("appattest\x00\x00\x00\x00\x00\x00\x00"),
					CredentialID: rawCredentialID,
					CoseKey: attest.CoseKey{
						Kty: 2,
						Alg: -7,
						Crv: 1,
						X:   publicKey.X.Bytes(),
						Y:   publicKey.Y.Bytes(),
					},
				},
			},
		},
		"valid authenticator data without attested credential, with extensions": {
			data: merge(
				sha2("1234567890.appleID"),     // RP ID hash
				[]byte{0x00},                   // flag: no attested credential (typical shape for assertion)
				[]byte{0x00, 0x00, 0x00, 0x05}, // counter = 5
				cborMap( // Extensions
					item{cborText("apple_validation_category_01"), cborBytes([]byte{0x01, 0x00, 0x00, 0x00})}, // apple_validation_category_01
					item{cborText("apple_bundle_version_01"), cborText("1.0")},                                // apple_bundle_version_01
				),
			),
			want: &attest.AuthenticatorData{
				RPIDHash:                sha2("1234567890.appleID"),
				Flags:                   0x00,
				Counter:                 5,
				AppleValidationCategory: 1,
				AppleBundleVersion:      "1.0",
			},
		},
		"valid authenticator data without attested credential": {
			data: merge(
				sha2("1234567890.appleID"),     // RP ID hash
				[]byte{0x01},                   // flag
				[]byte{0x00, 0x00, 0x00, 0x00}, // counter
			),
			want: &attest.AuthenticatorData{
				RPIDHash: sha2("1234567890.appleID"),
				Flags:    0x01,
				Counter:  0,
			},
		},
		"empty authenticator data": {
			data:    []byte{},
			wantErr: expectError("authenticator data length too short: got 0 bytes"),
		},
		"too short overall": { // shorter than minAuthDataLen (37 bytes)
			data: merge(
				sha2("1234567890.appleID"), // RP ID hash
				[]byte{0x01},               // flag
				[]byte{0x00, 0x00, 0x00},   // counter
			),
			wantErr: expectError("authenticator data length too short: got 36 bytes"),
		},
		"AT flag set but requireCred=false: credential not parsed": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x40},                   // flag: attested credential present
				[]byte{0x00, 0x00, 0x00, 0x00}, // counter
			),
			want: &attest.AuthenticatorData{
				RPIDHash: sha2("1234567890.appleID"),
				Flags:    0x40,
				Counter:  0,
			},
		},
		"requireCred=true but no attested credential data": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x40},
				[]byte{0x00, 0x00, 0x00, 0x00},
			),
			requireCred: true,
			wantErr:     expectError("failed to read AAGUID", io.ErrUnexpectedEOF),
		},
		"credential ID length exceeds available data": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x40},
				[]byte{0x00, 0x00, 0x00, 0x00},
				[]byte("appattest\x00\x00\x00\x00\x00\x00\x00"),
				[]byte{0x00, 0xFF}, // claims 255 bytes but none follow
			),
			requireCred: true,
			wantErr:     expectError("failed to read credential ID", io.ErrUnexpectedEOF),
		},
		"unknown extension key": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				cborMap(
					item{cborText("unknown_key_01"), cborUint(1)},
				),
			),
			wantErr: expectError("failed to parse extensions", attest.ErrUnknownKey),
		},
		"cose key parse error propagates": {
			data: merge(
				sha2("1234567890.appleID"),                                       // RP ID hash
				[]byte{0x40},                                                     // flag
				[]byte{0x00, 0x00, 0x00, 0x00},                                   // counter
				[]byte("appattest\x00\x00\x00\x00\x00\x00\x00"),                  // aaguid
				binary.BigEndian.AppendUint16(nil, uint16(len(rawCredentialID))), // CredID Len
				rawCredentialID,                                                  // CredID
				cborMap( // Cose Key with unknown key
					item{cborUint(9), cborUint(2)}, // unknown key type
				),
			),
			requireCred: true,
			wantErr:     expectError("failed to parse COSE key", attest.ErrUnknownKey),
		},
		"extensions not a map": {
			data: merge(
				sha2("1234567890.appleID"),     // RP ID hash
				[]byte{0x00},                   // flag: no attested credential
				[]byte{0x00, 0x00, 0x00, 0x00}, // counter
				[]byte{0x01},                   // not a map header (unsigned int 1)
			),
			wantErr: expectError(fmt.Sprintf("expected CBOR type Map (major type 5), got major type %d", cbor.UnsignedInt)),
		},
		"invalid extra key type": {
			data: merge(
				sha2("1234567890.appleID"),                                       // RP ID hash
				[]byte{0x40},                                                     // flag
				[]byte{0x00, 0x00, 0x00, 0x00},                                   // counter
				[]byte("appattest\x00\x00\x00\x00\x00\x00\x00"),                  // aaguid
				binary.BigEndian.AppendUint16(nil, uint16(len(rawCredentialID))), // CredID Len
				rawCredentialID,                                                  // CredID
				cborMap( // Cose Key
					item{cborUint(1), cborUint(2)},                       // ktv: EC2
					item{cborUint(3), cborNegInt(-7)},                    // alg: ES256
					item{cborNegInt(-1), cborUint(1)},                    // crv: P-256
					item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())}, // X
					item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())}, // Y
				),
				cborMap( // Extensions
					item{cborBytes([]byte("apple_validation_category_01")), cborUint(1)}, // apple_validation_category_01
					item{cborText("apple_bundle_version_01"), cborText("1.0")},           // apple_bundle_version_01
				),
			),
			requireCred: true,
			wantErr:     expectError(fmt.Sprintf("expected string map key at index %d, got major type %d", 0, cbor.ByteString)),
		},
		"trailing data after extensions": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				cborMap(
					item{cborText("apple_validation_category_01"), cborBytes([]byte{0x01, 0x00, 0x00, 0x00})}, // apple_validation_category_01
				),
				[]byte{0xFF}, // extra trailing byte
			),
			wantErr: expectError("unexpected trailing data in authenticator data"),
		},
		"category length 0": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				cborMap(
					item{cborText("apple_validation_category_01"), cborBytes([]byte{})},
				),
			),
			wantErr: expectError("invalid category length"),
		},
		"category length 3": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				cborMap(
					item{cborText("apple_validation_category_01"), cborBytes([]byte{0x01, 0x00, 0x00})},
				),
			),
			wantErr: expectError("invalid category length"),
		},
		"category length 5": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				cborMap(
					item{cborText("apple_validation_category_01"), cborBytes([]byte{0x01, 0x00, 0x00, 0x00, 0x00})},
				),
			),
			wantErr: expectError("invalid category length"),
		},
		"category wrong type": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				cborMap(
					item{cborText("apple_validation_category_01"), cborUint(1)},
				),
			),
			wantErr: expectError("expected bytestring for category"),
		},
		"bundle version wrong type": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				cborMap(
					item{cborText("apple_bundle_version_01"), cborUint(1)},
				),
			),
			wantErr: expectError("expected string for version"),
		},
		"bundle version only": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				cborMap(
					item{cborText("apple_bundle_version_01"), cborText("1.0")},
				),
			),
			want: &attest.AuthenticatorData{
				RPIDHash:           sha2("1234567890.appleID"),
				AppleBundleVersion: "1.0",
			},
		},
		"extensions: empty map": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				[]byte{0xa0}, // empty map
			),
			want: &attest.AuthenticatorData{RPIDHash: sha2("1234567890.appleID")},
		},
		"extensions: map size exceeds entries": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				[]byte{0xa2}, // map(2), but only 1 entry follows
				cborText("apple_bundle_version_01"), cborText("1.0"),
			),
			wantErr: expectError("failed to read map key header at index 1", io.ErrUnexpectedEOF),
		},
		"extensions: key string truncated": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				[]byte{0xa1, 0x78, 0x20}, // map(1), text string of 32 bytes declared
				[]byte("ab"),             // only 2 bytes follow
			),
			wantErr: expectError("failed to read map key string at index 0", io.ErrUnexpectedEOF),
		},
		"extensions: value header missing": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				[]byte{0xa1},
				cborText("apple_bundle_version_01"), // key only, no value
			),
			wantErr: expectError("failed to read map value header", io.ErrUnexpectedEOF),
		},
		"extensions: version string truncated": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				[]byte{0xa1},
				cborText("apple_bundle_version_01"),
				[]byte{0x65}, []byte("ab"), // text(5) declared, 2 bytes follow
			),
			wantErr: expectError("failed to read version", io.ErrUnexpectedEOF),
		},
		"extensions: category byte string truncated": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				[]byte{0xa1},
				cborText("apple_validation_category_01"),
				[]byte{0x44, 0x01, 0x02}, // bytes(4) declared, 2 bytes follow
			),
			wantErr: expectError("failed to read category", io.ErrUnexpectedEOF),
		},
		"requireCred=false but credential data present": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x40}, // AT flag on
				[]byte{0x00, 0x00, 0x00, 0x00},
				[]byte("appattest\x00\x00\x00\x00\x00\x00\x00"),
				binary.BigEndian.AppendUint16(nil, uint16(len(rawCredentialID))),
				rawCredentialID,
				cborMap(
					item{cborUint(1), cborUint(2)},
					item{cborUint(3), cborNegInt(-7)},
					item{cborNegInt(-1), cborUint(1)},
					item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())},
					item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())},
				),
			),
			requireCred: false,
			wantErr:     expectError("failed to parse extensions"),
		},
		"requireCred=true but no credential data (assertion shape)": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x05},
				cborMap(
					item{cborText("apple_validation_category_01"), cborBytes([]byte{0x01, 0x00, 0x00, 0x00})},
					item{cborText("apple_bundle_version_01"), cborText("1.0")},
				),
			),
			requireCred: true,
			wantErr:     expectError("failed to read"),
		},
		"duplicate extension: bundle version": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				cborMap(
					item{cborText("apple_bundle_version_01"), cborText("1.0")},
					item{cborText("apple_bundle_version_01"), cborText("2.0")},
				),
			),
			wantErr: expectError("apple_bundle_version_01", attest.ErrDuplicateKey),
		},
		"duplicate extension: validation category": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				cborMap(
					item{cborText("apple_validation_category_01"), cborBytes([]byte{0x01, 0x00, 0x00, 0x00})},
					item{cborText("apple_validation_category_01"), cborBytes([]byte{0x01, 0x00, 0x00, 0x00})},
				),
			),
			wantErr: expectError("apple_validation_category_01", attest.ErrDuplicateKey),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			auth := &attest.AuthenticatorData{}
			err := auth.Unmarshal(tt.data, tt.requireCred)
			if !assertErr(t, err, tt.wantErr) {
				return
			}

			if diff := cmp.Diff(tt.want, auth); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func generatePublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &privateKey.PublicKey
}
