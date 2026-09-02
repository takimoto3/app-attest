package attest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	attest "github.com/takimoto3/app-attest"
	"github.com/takimoto3/app-attest/cbor"
)

func TestAuthenticatorData_HasAttestedCredentialData(t *testing.T) {
	tests := map[string]struct {
		target *attest.AuthenticatorData
		want   bool
	}{
		"true case":  {&attest.AuthenticatorData{Flags: 0x40}, true},
		"false case": {&attest.AuthenticatorData{Flags: 0x10}, false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tt.target.HasAttestedCredentialData(); tt.want != got {
				t.Errorf("HasAttestedCredentialData() invalid result want %v got:%v", tt.want, got)
			}
		})
	}
}

func TestCoseKey_Unmarshal(t *testing.T) {
	publicKey := generatePublicKey(t)

	tests := map[string]struct {
		data    []byte
		wantKey *ecdsa.PublicKey
		wantErr error
	}{
		"empty bytes": {
			data:    []byte{},
			wantErr: fmt.Errorf("failed to read CBOR map header: %w", io.ErrUnexpectedEOF)},
		"map key not integer": {
			data: cborMap( // Cose Key
				item{cborText("1"), cborUint(2)},                     // ktv: EC2
				item{cborUint(3), cborNegInt(-7)},                    // alg: ES256
				item{cborNegInt(-1), cborUint(1)},                    // crv: P-256
				item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())}, // X
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())}, // Y
			),
			wantErr: fmt.Errorf("expected integer map key at index %d, got major type %d", 0, cbor.TextString)},
		"invalid key": {
			data: cborMap( // Cose Key
				item{cborUint(9), cborUint(2)},                       // ktv: EC2
				item{cborUint(3), cborNegInt(-7)},                    // alg: ES256
				item{cborNegInt(-1), cborUint(1)},                    // crv: P-256
				item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())}, // X
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())}, // Y
			),
			wantErr: fmt.Errorf("%w: %d", attest.ErrUnknownKey, 9)},
		"truncated map": {
			data: []byte{
				0xa5, // map(5) — but only 1 entry follows
				0x01, 0x02,
			},
			wantErr: fmt.Errorf("failed to read map key header at index 1"),
		},
		"wrong type for byte string value": {
			data: cborMap(
				item{cborUint(1), cborUint(2)},
				item{cborUint(3), cborNegInt(-7)},
				item{cborNegInt(-1), cborUint(1)},
				item{cborNegInt(-2), cborUint(123)}, // X should be bytes, not uint
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())},
			),
			wantErr: fmt.Errorf("expected ByteString for X coordinate"),
		},
		"valid cose key": {
			data: cborMap( // Cose Key
				item{cborUint(1), cborUint(2)},                       // ktv: EC2
				item{cborUint(3), cborNegInt(-7)},                    // alg: ES256
				item{cborNegInt(-1), cborUint(1)},                    // crv: P-256
				item{cborNegInt(-2), cborBytes(publicKey.X.Bytes())}, // X
				item{cborNegInt(-3), cborBytes(publicKey.Y.Bytes())}, // Y
			),
			wantKey: publicKey},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var coseKey attest.CoseKey
			dec := cbor.NewDecoder(tt.data)
			err := coseKey.UnmarshalCBOR(dec)
			if err != nil {
				if tt.wantErr == nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Errorf("UnmarshalCBOR() error = %q, want error containing %q", err.Error(), tt.wantErr.Error())
				}
				return
			}
			if tt.wantErr != nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr.Error())
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
		"short X": {x: make([]byte, 31), y: make([]byte, 32)},
		"short Y": {x: make([]byte, 32), y: make([]byte, 31)},
		"empty":   {x: nil, y: nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			k := &attest.CoseKey{X: tt.x, Y: tt.y}
			_, err := k.ParsePublicKey()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
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
		data    []byte
		want    *attest.AuthenticatorData
		wantErr error
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
					item{cborText("apple_validation_category_01"), cborUint(1)}, // apple_validation_category_01
					item{cborText("apple_bundle_version_01"), cborText("1.0")},  // apple_bundle_version_01
				),
			),
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
				[]byte{0x00},                   // flag: no attested credential (assertion に典型的な形)
				[]byte{0x00, 0x00, 0x00, 0x05}, // counter = 5
				cborMap( // Extensions
					item{cborText("apple_validation_category_01"), cborUint(1)}, // apple_validation_category_01
					item{cborText("apple_bundle_version_01"), cborText("1.0")},  // apple_bundle_version_01
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
			wantErr: fmt.Errorf("authenticator data length too short: got 0 bytes"),
		},
		"too short overall": { // shorter than minAuthDataLen (37 bytes)
			data: merge(
				sha2("1234567890.appleID"), // RP ID hash
				[]byte{0x01},               // flag
				[]byte{0x00, 0x00, 0x00},   // counter
			),
			wantErr: fmt.Errorf("authenticator data length too short: got 36 bytes"),
		},
		"flag set but no attested credential data": {
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
		"credential ID length exceeds available data": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x40},
				[]byte{0x00, 0x00, 0x00, 0x00},
				[]byte("appattest\x00\x00\x00\x00\x00\x00\x00"),
				[]byte{0x00, 0xFF}, // claims 255 bytes but none follow
			),
			wantErr: fmt.Errorf("failed to read credential ID"),
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
			wantErr: fmt.Errorf("%w: %s", attest.ErrUnknownKey, "unknown_key_01"),
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
			wantErr: fmt.Errorf("%w: %d", attest.ErrUnknownKey, 9),
		},
		"extensions not a map": {
			data: merge(
				sha2("1234567890.appleID"),     // RP ID hash
				[]byte{0x00},                   // flag: no attested credential
				[]byte{0x00, 0x00, 0x00, 0x00}, // counter
				[]byte{0x01},                   // not a map header (unsigned int 1)
			),
			wantErr: fmt.Errorf("expected CBOR type Map (major type 5), got major type %d", cbor.UnsignedInt),
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
			wantErr: fmt.Errorf("expected string map key at index %d, got major type %d", 0, cbor.ByteString),
		},
		"trailing data after extensions": {
			data: merge(
				sha2("1234567890.appleID"),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x00},
				cborMap(
					item{cborText("apple_validation_category_01"), cborUint(1)},
				),
				[]byte{0xFF}, // extra trailing byte
			),
			wantErr: fmt.Errorf("unexpected trailing data in authenticator data"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			auth := &attest.AuthenticatorData{}
			err := auth.Unmarshal(tt.data)
			if err != nil {
				if tt.wantErr == nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Errorf("ParseAuthData() error = %q, want error containing %q", err.Error(), tt.wantErr.Error())
				}
				return
			}
			if tt.wantErr != nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr.Error())
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
