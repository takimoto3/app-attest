package attest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	attest "github.com/takimoto3/app-attest"
	"github.com/takimoto3/app-attest/cbor"
)

func newAssertionObj(tb testing.TB, key *ecdsa.PrivateKey, authData, clientData []byte) *attest.AssertionObject {
	tb.Helper()

	clientDataHash := sha256.Sum256(clientData)
	hash := sha256.New()
	hash.Write(authData)
	hash.Write(clientDataHash[:])
	digest := sha256.Sum256(hash.Sum(nil))

	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		tb.Fatal(err)
	}
	return &attest.AssertionObject{Signature: sig, AuthData: authData}
}

func TestAssertionService_VerifyWithState(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 末尾1バイトを反転したコピーを返す
	flip := func(b []byte) []byte {
		c := bytes.Clone(b)
		c[len(c)-1] ^= 0xff
		return c
	}
	const (
		appID     = "1234567890.com.example.myapp"
		challenge = "example_server_challenge"
	)
	clientData := []byte(`{"challenge":"` + challenge + `"}`)

	assertionObj := newAssertionObj(t, key,
		merge(
			sha2(appID),                    // RP ID hash
			[]byte{0x40},                   // flags
			[]byte{0x00, 0x00, 0x00, 0x01}, // counter
			cborMap( // Extensions
				item{cborText("apple_validation_category_01"), cborBytes([]byte{0x04, 0x00, 0x00, 0x00})}, // App Store (little-endian uint32)
				item{cborText("apple_bundle_version_01"), cborText("42")},
			),
		), clientData)

	tests := map[string]struct {
		assertionObj *attest.AssertionObject
		challenge    string
		clientData   []byte
		state        attest.AssertionState
		want         *attest.AssertionResult
		wantErr      error
	}{
		"success": {
			assertionObj: assertionObj,
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				PublicKey: &key.PublicKey,
				Challenge: "example_server_challenge",
				Counter:   0,
			},
			want: &attest.AssertionResult{
				Counter:                 1,
				AppleBundleVersion:      "42",
				AppleValidationCategory: attest.ValidationCategoryAppStore,
			},
		},
		"success: no extensions": {
			assertionObj: newAssertionObj(t, key,
				merge(
					sha2(appID),                    // RP ID hash
					[]byte{0x00},                   // flags
					[]byte{0x00, 0x00, 0x00, 0x01}, // counter
				), clientData),
			challenge:  challenge,
			clientData: clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				PublicKey: &key.PublicKey,
				Challenge: "example_server_challenge",
				Counter:   0,
			},
			want: &attest.AssertionResult{
				Counter:                 1,
				AppleBundleVersion:      "",
				AppleValidationCategory: attest.ValidationCategoryInvalid,
			},
		},
		"error: assertion object is nil": {
			challenge:  challenge,
			clientData: clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				PublicKey: &key.PublicKey,
				Challenge: "example_server_challenge",
				Counter:   0,
			},
			wantErr: errors.New("assertion object is nil"),
		},
		"error: public key is nil": {
			assertionObj: assertionObj,
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				Challenge: "example_server_challenge",
				Counter:   0,
			},
			wantErr: errors.New("assertion state: PublicKey is nil or incomplete"),
		},
		"error: public key has nil curve": {
			assertionObj: assertionObj,
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				Challenge: "example_server_challenge",
				PublicKey: &ecdsa.PublicKey{X: key.PublicKey.X, Y: key.PublicKey.Y},
				Counter:   0,
			},
			wantErr: errors.New("assertion state: PublicKey is nil or incomplete"),
		},
		"error: public key has nil X": {
			assertionObj: assertionObj,
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     appID,
				PublicKey: &ecdsa.PublicKey{Curve: key.PublicKey.Curve, Y: key.PublicKey.Y},
				Challenge: challenge,
			},
			wantErr: errors.New("PublicKey is nil or incomplete"),
		},
		"error: public key has nil Y": {
			assertionObj: assertionObj,
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     appID,
				PublicKey: &ecdsa.PublicKey{Curve: key.PublicKey.Curve, X: key.PublicKey.X},
				Challenge: challenge,
			},
			wantErr: errors.New("PublicKey is nil or incomplete"),
		},
		"error: signature is nil": {
			assertionObj: &attest.AssertionObject{Signature: nil, AuthData: assertionObj.AuthData},
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				PublicKey: &key.PublicKey,
				Challenge: "example_server_challenge",
				Counter:   0,
			},
			wantErr: attest.ErrInvalidSignature,
		},
		"error: signature is empty": {
			assertionObj: &attest.AssertionObject{Signature: []byte{}, AuthData: assertionObj.AuthData},
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				PublicKey: &key.PublicKey,
				Challenge: "example_server_challenge",
				Counter:   0,
			},
			wantErr: attest.ErrInvalidSignature,
		},
		"error: signature is not valid ASN.1": {
			assertionObj: &attest.AssertionObject{Signature: []byte("garbage"), AuthData: assertionObj.AuthData},
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				PublicKey: &key.PublicKey,
				Challenge: "example_server_challenge",
				Counter:   0,
			},
			wantErr: attest.ErrInvalidSignature,
		},
		"error: signature is corrupted": {
			assertionObj: &attest.AssertionObject{Signature: flip(assertionObj.Signature), AuthData: assertionObj.AuthData},
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				PublicKey: &key.PublicKey,
				Challenge: "example_server_challenge",
				Counter:   0,
			},
			wantErr: attest.ErrInvalidSignature,
		},
		"error: signed with a different key": {
			assertionObj: newAssertionObj(t, otherKey, assertionObj.AuthData, clientData),
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				PublicKey: &key.PublicKey,
				Challenge: "example_server_challenge",
				Counter:   0,
			},
			wantErr: attest.ErrInvalidSignature,
		},
		"error: clientData was tampered": {
			assertionObj: assertionObj,
			challenge:    challenge,
			clientData:   []byte(`{"challenge":"tampered"}`), // Pass a clientData different from the one used when signing
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				PublicKey: &key.PublicKey,
				Challenge: "example_server_challenge",
				Counter:   0,
			},
			wantErr: attest.ErrInvalidSignature,
		},
		"error: authData was tampered": {
			assertionObj: &attest.AssertionObject{Signature: assertionObj.Signature, AuthData: flip(assertionObj.AuthData)},
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				PublicKey: &key.PublicKey,
				Challenge: "example_server_challenge",
				Counter:   0,
			},
			wantErr: attest.ErrInvalidSignature,
		},
		"error: state public key differs from signing key": {
			assertionObj: assertionObj,
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     appID,
				PublicKey: &otherKey.PublicKey, // Only the verifying key is different
				Challenge: challenge,
			},
			wantErr: attest.ErrInvalidSignature,
		},
		"error: authData is too short": {
			assertionObj: newAssertionObj(t, key, []byte{}, clientData), // Empty authData, correctly signed
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				PublicKey: &key.PublicKey,
				Challenge: "example_server_challenge",
				Counter:   0,
			},
			wantErr: errors.New("authenticator data decoding failed"),
		},
		"error: authData has invalid extensions": {
			assertionObj: newAssertionObj(t, key,
				merge(sha2(appID), []byte{0x00}, []byte{0x00, 0x00, 0x00, 0x01}, []byte{0x01}), // Extensions is not a map
				clientData),
			challenge:  challenge,
			clientData: clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.myapp",
				PublicKey: &key.PublicKey,
				Challenge: "example_server_challenge",
				Counter:   0,
			},
			wantErr: errors.New("authenticator data decoding failed"),
		},
		"error: app ID mismatch": {
			assertionObj: assertionObj,
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     "1234567890.com.example.otherapp", // Different from the app ID in authData
				PublicKey: &key.PublicKey,
				Challenge: challenge,
			},
			wantErr: attest.ErrUnmatchRPIDHash,
		},
		"error: app ID is empty": {
			assertionObj: assertionObj,
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     "",
				PublicKey: &key.PublicKey,
				Challenge: challenge,
			},
			wantErr: attest.ErrUnmatchRPIDHash,
		},
		"error: RP ID hash in authData is for a different app": {
			assertionObj: newAssertionObj(t, key,
				merge(sha2("1234567890.com.example.otherapp"), []byte{0x00}, []byte{0x00, 0x00, 0x00, 0x01}),
				clientData), // Correctly signed authData whose RP ID hash is for another app
			challenge:  challenge,
			clientData: clientData,
			state: attest.AssertionState{
				AppID:     appID,
				PublicKey: &key.PublicKey,
				Challenge: challenge,
			},
			wantErr: attest.ErrUnmatchRPIDHash,
		},
		"error: counter equals previous": {
			assertionObj: assertionObj, // authData counter = 1
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     appID,
				PublicKey: &key.PublicKey,
				Challenge: challenge,
				Counter:   1, // Same as the counter in authData
			},
			wantErr: errors.New("counter was not greater than previous"),
		},
		"error: counter is less than previous": {
			assertionObj: assertionObj,
			challenge:    challenge,
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     appID,
				PublicKey: &key.PublicKey,
				Challenge: challenge,
				Counter:   5, // Greater than the counter in authData
			},
			wantErr: errors.New("counter was not greater than previous"),
		},
		"error: counter is zero on first assertion": {
			assertionObj: newAssertionObj(t, key,
				merge(sha2(appID), []byte{0x00}, []byte{0x00, 0x00, 0x00, 0x00}), // counter = 0
				clientData),
			challenge:  challenge,
			clientData: clientData,
			state: attest.AssertionState{
				AppID:     appID,
				PublicKey: &key.PublicKey,
				Challenge: challenge,
				Counter:   0,
			},
			wantErr: errors.New("counter was not greater than previous"),
		},
		"error: challenge mismatch": {
			assertionObj: assertionObj,
			challenge:    "other_challenge", // Different from state.Challenge
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     appID,
				PublicKey: &key.PublicKey,
				Challenge: challenge,
			},
			wantErr: errors.New("invalid challenge"),
		},
		"error: challenge is empty": {
			assertionObj: assertionObj,
			challenge:    "", // Empty challenge from the client
			clientData:   clientData,
			state: attest.AssertionState{
				AppID:     appID,
				PublicKey: &key.PublicKey,
				Challenge: challenge,
			},
			wantErr: errors.New("invalid challenge"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Run("VerifyWithState", func(t *testing.T) {
				service := attest.AssertionService{}

				got, err := service.VerifyWithState(tt.assertionObj, tt.challenge, tt.clientData, tt.state)
				if err != nil {
					if tt.wantErr == nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if !strings.Contains(err.Error(), tt.wantErr.Error()) {
						t.Errorf("err = %q, want it to contain %q", err, tt.wantErr)
					}
					return
				}
				if tt.wantErr != nil {
					t.Fatalf("expected error containing %q, got result %+v", tt.wantErr, got)
				}
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
			})
			t.Run("Verify(deprecated)", func(t *testing.T) {
				service := attest.AssertionService{
					AppID:     tt.state.AppID,
					Challenge: tt.state.Challenge,
					PublicKey: tt.state.PublicKey,
					Counter:   tt.state.Counter,
				}

				got, err := service.Verify(tt.assertionObj, tt.challenge, tt.clientData)
				if err != nil {
					if tt.wantErr == nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if !strings.Contains(err.Error(), tt.wantErr.Error()) {
						t.Errorf("err = %q, want it to contain %q", err, tt.wantErr)
					}
					return
				}
				if tt.wantErr != nil {
					t.Fatalf("expected error containing %q, got result %+v", tt.wantErr, got)
				}
				if got != tt.want.Counter {
					t.Errorf("counter = %d, want %d", got, tt.want.Counter)
				}
			})
		})
	}
}

func TestAssertionObject_UnmarshalCBOR(t *testing.T) {
	authData := cborMap(
		item{cborText("authenticatorData"), cborBytes(merge(
			[]byte{ // RP ID hash (32 bytes)
				0x45, 0x65, 0x12, 0xea, 0x7e, 0x26, 0x94, 0x76, 0xab, 0x93, 0xe1, 0xb7, 0x97, 0x16, 0x85, 0x59,
				0x2f, 0xf7, 0x3f, 0x89, 0x4a, 0xc0, 0xec, 0x2f, 0xd5, 0x48, 0x08, 0xa0, 0x8b, 0xfb, 0x6c, 0x8f,
			},
			[]byte{0x40},                   // flags
			[]byte{0x00, 0x00, 0x00, 0x01}, // counter
			cborMap( // Extensions
				item{cborText("apple_validation_category_01"), []byte{0x44, 0x01, 0x00, 0x00, 0x00}},
				item{cborText("apple_bundle_version_01"), cborText("1.0")}, // apple_bundle_version_01
			),
		))},
	)

	tests := map[string]struct {
		data    []byte
		want    *attest.AssertionObject
		wantErr error
	}{
		"valid: signature and authenticatorData": {
			data: cborMap(
				item{cborText("signature"), cborBytes([]byte("sig-bytes"))},
				item{cborText("authenticatorData"), cborBytes(authData)},
			),
			want: &attest.AssertionObject{
				Signature: []byte("sig-bytes"),
				AuthData:  authData,
			},
		},
		"empty data": {
			data:    []byte{},
			wantErr: io.ErrUnexpectedEOF,
		},
		"not a map": {
			data:    cborUint(1),
			wantErr: fmt.Errorf("expected CBOR type Map (major type 5) for AssertionObject, got major type %d", cbor.UnsignedInt),
		},
		"map key not text": {
			data: cborMap(
				item{cborUint(1), cborText("sig")},
			),
			wantErr: fmt.Errorf("expected string map key at index %d, got major type %d", 0, cbor.UnsignedInt),
		},
		"signature wrong value type": {
			data: cborMap(
				item{cborText("signature"), cborUint(1)},
			),
			wantErr: fmt.Errorf(`expected bytestring for signature (key "signature"), got major type %d`, cbor.UnsignedInt),
		},
		"authenticatorData wrong value type": {
			data: cborMap(
				item{cborText("authenticatorData"), cborText("not-bytes")},
			),
			wantErr: fmt.Errorf(`expected bytestring for authData (key "authenticatorData"), got major type %d`, cbor.TextString),
		},
		"unknown key": {
			data: cborMap(
				item{cborText("unknown_key"), cborUint(1)},
			),
			wantErr: attest.ErrUnknownKey,
		},
		"only signature present (authenticatorData omitted)": {
			data: cborMap(
				item{cborText("signature"), cborBytes([]byte("sig-bytes"))},
			),
			wantErr: errors.New("missing required keys"),
		},
		"only authenticatorData present (signature omitted)": {
			data: cborMap(
				item{cborText("authenticatorData"), cborBytes(authData)},
			),
			wantErr: errors.New("missing required keys"),
		},
		"map size is truncated": {
			data:    []byte{0xb8}, // map with a 1-byte length that is missing
			wantErr: errors.New("failed to read CBOR map size"),
		},
		"map has no entries despite declared size": {
			data:    []byte{0xa1}, // map(1) with no entries
			wantErr: errors.New("failed to read map key header at index 0"),
		},
		"map key string is truncated": {
			data:    []byte{0xa1, 0x69, 's'}, // text(9) but only 1 byte
			wantErr: errors.New("failed to read map key string at index 0"),
		},
		"signature value is missing": {
			data:    merge([]byte{0xa1}, cborText("signature")),
			wantErr: errors.New(`failed to read map value header (key "signature")`),
		},
		"signature bytes are truncated": {
			data:    merge([]byte{0xa1}, cborText("signature"), []byte{0x45, 'a'}), // bytes(5) but only 1 byte
			wantErr: errors.New("failed to read signature bytes"),
		},
		"authenticatorData value is missing": {
			data:    merge([]byte{0xa1}, cborText("authenticatorData")),
			wantErr: errors.New(`failed to read map value header (key "authenticatorData")`),
		},
		"authenticatorData bytes are truncated": {
			data:    merge([]byte{0xa1}, cborText("authenticatorData"), []byte{0x45, 'a'}),
			wantErr: errors.New("failed to read authData bytes"),
		},
		"duplicate key: last value wins": {
			data: cborMap(
				item{cborText("signature"), cborBytes([]byte("first"))},
				item{cborText("signature"), cborBytes([]byte("second"))},
				item{cborText("authenticatorData"), cborBytes(authData)},
			),
			want: &attest.AssertionObject{
				Signature: []byte("second"), // The later value overwrites the earlier one
				AuthData:  authData,
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var ao attest.AssertionObject
			err := ao.UnmarshalCBOR(tt.data)
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

			if diff := cmp.Diff(tt.want, &ao); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func BenchmarkAssertionObject_UnmarshalCBOR(b *testing.B) {
	data := cborMap(
		item{cborText("authenticatorData"), cborBytes(merge(
			[]byte{ // RP ID hash (32 bytes)
				0x45, 0x65, 0x12, 0xea, 0x7e, 0x26, 0x94, 0x76, 0xab, 0x93, 0xe1, 0xb7, 0x97, 0x16, 0x85, 0x59,
				0x2f, 0xf7, 0x3f, 0x89, 0x4a, 0xc0, 0xec, 0x2f, 0xd5, 0x48, 0x08, 0xa0, 0x8b, 0xfb, 0x6c, 0x8f,
			},
			[]byte{0x40},                   // flags: AT bit set (real Apple devices set this even without credential data)
			[]byte{0x00, 0x00, 0x00, 0x01}, // counter = 1
			cborMap( // Extensions
				item{cborText("apple_validation_category_01"), []byte{0x44, 0x01, 0x00, 0x00, 0x00}},
				item{cborText("apple_bundle_version_01"), cborText("1.0")}, // apple_bundle_version_01
			),
		))},
		item{cborText("signature"), cborBytes([]byte{
			0x30, 0x44, 0x02, 0x20, 0x49, 0xe8, 0x14, 0xff, 0x41, 0x1e, 0xbc, 0xf5, 0x42, 0xb2, 0xf3, 0x86, 0x32, 0x37, 0x74, 0x43, 0xc9, 0xd6, 0x03, 0xf4,
			0xa5, 0x50, 0xd8, 0x14, 0xd1, 0x2b, 0xec, 0x75, 0x8b, 0xc7, 0xb3, 0xa8, 0x02, 0x20, 0x18, 0xce, 0xc1, 0xb1, 0x96, 0xd2, 0xb8, 0x5e, 0x93, 0x8e,
			0x62, 0xba, 0xc6, 0xd3, 0x85, 0x7a, 0x4c, 0x95, 0xca, 0x37, 0xfc, 0x6a, 0x41, 0xaf, 0xa7, 0x9a, 0x85, 0x44, 0x69, 0xbd, 0x2d, 0x3c,
		})},
	)
	b.ResetTimer()

	for i := 0; b.Loop(); i++ {
		var ao attest.AssertionObject
		if err := ao.UnmarshalCBOR(data); err != nil {
			b.Fatal(err)
		}
	}
}
