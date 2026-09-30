package attest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"testing"

	attest "github.com/takimoto3/app-attest"
	"github.com/takimoto3/app-attest/testutils"
)

type StoredData struct {
	Challenge string
	Counter   uint32
}

func TestAssertionService_Verify(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	genPubKeyData, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	testData, err := testutils.LoadTestData()
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		appID      string
		assertData []byte
		clientData []byte
		challenge  string
		stored     StoredData
		newCounter uint32
		pubkey     []byte
		wantErr    error
	}{
		"Success Case": {
			testData.Assertion.AppID,
			testData.Assertion.Assertion,
			testData.Assertion.ClientData,
			string(testData.Assertion.Challenge),
			StoredData{
				Challenge: string(testData.Assertion.Challenge),
				Counter:   0,
			},
			1,
			testData.Assertion.PublicKey,
			nil,
		},
		"Error Case:different public key use": {
			testData.Assertion.AppID,
			testData.Assertion.Assertion,
			testData.Assertion.ClientData,
			string(testData.Assertion.Challenge),
			StoredData{
				Challenge: string(testData.Assertion.Challenge),
				Counter:   0,
			},
			1,
			genPubKeyData,
			attest.ErrInvalidSignature,
		},
		"Error Case:empty request body use": {
			testData.Assertion.AppID,
			testData.Assertion.Assertion,
			[]byte{},
			string(testData.Assertion.Challenge),
			StoredData{
				Challenge: string(testData.Assertion.Challenge),
				Counter:   0,
			},
			0,
			testData.Assertion.PublicKey,
			attest.ErrInvalidSignature,
		},
		"Error Case:client data contains invalid challenge use": {
			testData.Assertion.AppID,
			testData.Assertion.Assertion,
			bytes.Replace(testData.Assertion.ClientData, testData.Assertion.Challenge, []byte("xxxxxxxxxxxxxxxx"), 1),
			string(testData.Assertion.Challenge),
			StoredData{
				Challenge: string(testData.Assertion.Challenge),
				Counter:   0,
			},
			0,
			testData.Assertion.PublicKey,
			attest.ErrInvalidSignature,
		},
		"Error Case:invalid challenge use": {
			testData.Assertion.AppID,
			testData.Assertion.Assertion,
			testData.Assertion.ClientData,
			"xxxxxxxxxxxxxxxx",
			StoredData{
				Challenge: string(testData.Assertion.Challenge),
				Counter:   0,
			},
			1,
			testData.Assertion.PublicKey,
			fmt.Errorf("invalid challenge expected: %s, received: xxxxxxxxxxxxxxxx", string(testData.Assertion.Challenge)),
		},
		"Error Case:invalid stored challenge use": {
			testData.Assertion.AppID,
			testData.Assertion.Assertion,
			testData.Assertion.ClientData,
			string(testData.Assertion.Challenge),
			StoredData{
				Challenge: "xxxxxxxxxxxxxxxx",
				Counter:   0,
			},
			1,
			testData.Assertion.PublicKey,
			fmt.Errorf("invalid challenge expected: xxxxxxxxxxxxxxxx, received: %s", string(testData.Assertion.Challenge)),
		},
		"Error Case:invalid AppID use": {
			"org.sample.AttestSample",
			testData.Assertion.Assertion,
			testData.Assertion.ClientData,
			string(testData.Assertion.Challenge),
			StoredData{
				Challenge: string(testData.Assertion.Challenge),
				Counter:   0,
			},
			1,
			testData.Assertion.PublicKey,
			attest.ErrUnmatchRPIDHash,
		},
		"Error Case:lower counter use": {
			testData.Assertion.AppID,
			testData.Assertion.Assertion,
			testData.Assertion.ClientData,
			string(testData.Assertion.Challenge),
			StoredData{
				Challenge: string(testData.Assertion.Challenge),
				Counter:   3,
			},
			1,
			testData.Assertion.PublicKey,
			fmt.Errorf("counter was not greater than previous [1, previous: 3]"),
		},
		"Error Case:nil public key": {
			testData.Assertion.AppID,
			testData.Assertion.Assertion,
			testData.Assertion.ClientData,
			string(testData.Assertion.Challenge),
			StoredData{
				Challenge: string(testData.Assertion.Challenge),
				Counter:   0,
			},
			1,
			nil, // pubkey
			errors.New("assertion state: PublicKey is nil"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var pubkey *ecdsa.PublicKey
			if tt.pubkey != nil {
				pubany, err := x509.ParsePKIXPublicKey(tt.pubkey)
				if err != nil {
					t.Fatal(err)
				}
				pubkey = pubany.(*ecdsa.PublicKey)
			}

			assertionObject := &attest.AssertionObject{}
			err = assertionObject.UnmarshalCBOR(tt.assertData)
			if err != nil {
				t.Fatal(err)
			}

			t.Run("VerifyWithState", func(t *testing.T) {
				state := attest.AssertionState{
					AppID:     tt.appID,
					PublicKey: pubkey,
					Challenge: tt.stored.Challenge,
					Counter:   tt.stored.Counter,
				}
				got, err := (&attest.AssertionService{}).VerifyWithState(assertionObject, tt.challenge, tt.clientData, state)
				if !IsEquals(tt.wantErr, err) {
					t.Fatal(err)
				}
				if err == nil && got.Counter != tt.newCounter {
					t.Errorf("invalid new counter want: %d, got: %d", tt.newCounter, got.Counter)
				}
			})

			t.Run("Verify (deprecated wrapper)", func(t *testing.T) {
				target := attest.AssertionService{
					AppID:     tt.appID,
					Challenge: tt.stored.Challenge,
					Counter:   tt.stored.Counter,
					PublicKey: pubkey,
				}
				//nolint:staticcheck // intentionally covering the deprecated API for backward compatibility
				got, err := target.Verify(assertionObject, tt.challenge, tt.clientData)
				if !IsEquals(tt.wantErr, err) {
					t.Fatal(err)
				}
				if err == nil && got != tt.newCounter {
					t.Errorf("invalid new counter want: %d, got: %d", tt.newCounter, got)
				}
			})
		})
	}
}

func TestAssertionService_VerifyWithState_Extensions(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const (
		appID     = "1234567890.com.example.myapp"
		challenge = "example_server_challenge"
	)
	clientData := []byte(`{"challenge":"` + challenge + `"}`)

	tests := map[string]struct {
		authData     []byte
		wantVersion  string
		wantCategory attest.ValidationCategory
	}{
		"App Store": {
			authData: merge(
				sha2(appID),                    // RP ID hash
				[]byte{0x00},                   // flags: no attested credential data
				[]byte{0x00, 0x00, 0x00, 0x01}, // counter = 1
				cborMap( // Extensions
					item{cborText("apple_validation_category_01"), cborBytes([]byte{0x04, 0x00, 0x00, 0x00})}, // App Store (little-endian uint32)
					item{cborText("apple_bundle_version_01"), cborText("42")},
				),
			),
			wantVersion:  "42",
			wantCategory: attest.ValidationCategoryAppStore,
		},
		"TestFlight": {
			authData: merge(
				sha2(appID),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x01},
				cborMap(
					item{cborText("apple_validation_category_01"), cborBytes([]byte{0x02, 0x00, 0x00, 0x00})},
					item{cborText("apple_bundle_version_01"), cborText("7")},
				),
			),
			wantVersion:  "7",
			wantCategory: attest.ValidationCategoryTestFlight,
		},
		"unknown category is kept": {
			authData: merge(
				sha2(appID),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x01},
				cborMap(
					item{cborText("apple_validation_category_01"), cborBytes([]byte{0x63, 0x00, 0x00, 0x00})}, // 99
					item{cborText("apple_bundle_version_01"), cborText("1")},
				),
			),
			wantVersion:  "1",
			wantCategory: attest.ValidationCategory(99),
		},
		"no extensions (iOS 26 and earlier)": {
			authData: merge(
				sha2(appID),
				[]byte{0x00},
				[]byte{0x00, 0x00, 0x00, 0x01},
			),
			wantVersion:  "",
			wantCategory: attest.ValidationCategoryInvalid,
		},
	}

	state := attest.AssertionState{AppID: appID, PublicKey: &key.PublicKey, Challenge: challenge}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// The client signs SHA256(nonce), where
			// nonce = SHA256(authData || SHA256(clientData)).
			clientDataHash := sha256.Sum256(clientData)
			h := sha256.New()
			h.Write(tt.authData)
			h.Write(clientDataHash[:])
			nonceHash := sha256.Sum256(h.Sum(nil))
			sig, err := ecdsa.SignASN1(rand.Reader, key, nonceHash[:])
			if err != nil {
				t.Fatal(err)
			}
			obj := &attest.AssertionObject{Signature: sig, AuthData: tt.authData}

			got, err := (&attest.AssertionService{}).VerifyWithState(obj, challenge, clientData, state)
			if err != nil {
				t.Fatal(err)
			}
			if got.Counter != 1 {
				t.Errorf("Counter = %d, want 1", got.Counter)
			}
			if got.AppleBundleVersion != tt.wantVersion {
				t.Errorf("AppleBundleVersion = %q, want %q", got.AppleBundleVersion, tt.wantVersion)
			}
			if got.AppleValidationCategory != tt.wantCategory {
				t.Errorf("AppleValidationCategory = %v, want %v", got.AppleValidationCategory, tt.wantCategory)
			}
		})
	}
}

const AssertionObjectB64 = "omlzaWduYXR1cmVYRjBEAiBJ6BT/QR689UKy84YyN3RDydYD9KVQ2BTRK+x1i8ezqAIgGM7BsZbSuF6TjmK6xtOFekyVyjf8akGvp5qFRGm9LTxxYXV0aGVudGljYXRvckRhdGFYJUVlEup+JpR2q5Pht5cWhVkv9z+JSsDsL9VICKCL+2yPQAAAAAE="

func TestAssertionObject_UnmarshalCBOR(t *testing.T) {
	data := testutils.DecodeB64(AssertionObjectB64)

	var ao attest.AssertionObject
	if err := ao.UnmarshalCBOR(data); err != nil {
		t.Fatalf("UnmarshalCBOR failed: %v", err)
	}

	wantAuthData := testutils.DecodeB64("RWUS6n4mlHark+G3lxaFWS/3P4lKwOwv1UgIoIv7bI9AAAAAAQ==")
	if !reflect.DeepEqual(wantAuthData, ao.AuthData) {
		t.Error("AssertionObject.AuthData unmatched")
	}
	wantSignature := testutils.DecodeB64("MEQCIEnoFP9BHrz1QrLzhjI3dEPJ1gP0pVDYFNEr7HWLx7OoAiAYzsGxltK4XpOOYrrG04V6TJXKN/xqQa+nmoVEab0tPA==")
	if !reflect.DeepEqual(wantSignature, ao.Signature) {
		t.Error("AssertionObject.Signature unmatched")
	}
}

func BenchmarkAssertionObject_UnmarshalCBOR(b *testing.B) {
	data := testutils.DecodeB64(AssertionObjectB64)

	b.ResetTimer()

	for i := 0; b.Loop(); i++ {
		var ao attest.AssertionObject
		if err := ao.UnmarshalCBOR(data); err != nil {
			b.Fatal(err)
		}
	}
}
