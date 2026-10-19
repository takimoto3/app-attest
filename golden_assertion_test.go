package attest_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	attest "github.com/takimoto3/app-attest"
)

func TestGolden_AssertionService_Verify(t *testing.T) {
	filepath := "testdata/golden_assertion.json"
	b, err := os.ReadFile(filepath)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skipf("golden case not found: %s", filepath)
	}
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		TeamIdentifier   string `json:"teamIdentifier"`
		BundleIdentifier string `json:"bundleIdentifier"`
		AssertionBase64  string `json:"assertionBase64"`
		ChallengeBase64  string `json:"challengeBase64"`
		ClientDataBase64 string `json:"clientDataBase64"`
		PublicKeyPEM     string `json:"publicKeyPEM"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(raw.PublicKeyPEM))
	if block == nil {
		t.Fatal("invalid PEM in publicKey")
	}
	fixture := struct {
		AppID      string
		Assertion  []byte
		ClientData []byte
		Challenge  []byte
		PublicKey  []byte // PKIX DER
	}{
		AppID:      raw.TeamIdentifier + "." + raw.BundleIdentifier,
		Assertion:  must(base64.StdEncoding.DecodeString(raw.AssertionBase64)),
		ClientData: must(base64.StdEncoding.DecodeString(raw.ClientDataBase64)),
		Challenge:  must(base64.StdEncoding.DecodeString(raw.ChallengeBase64)),
		PublicKey:  block.Bytes,
	}

	//	t.Logf("fixture: %+v\n", fixture)

	type StoredData struct {
		Challenge string
		Counter   uint32
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
			fixture.AppID,
			fixture.Assertion,
			fixture.ClientData,
			string(fixture.Challenge),
			StoredData{
				Challenge: string(fixture.Challenge),
				Counter:   0,
			},
			1,
			fixture.PublicKey,
			nil,
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
			if err := assertionObject.UnmarshalCBOR(tt.assertData); err != nil {
				t.Fatal(err)
			}

			t.Run("VerifyWithState", func(t *testing.T) {
				state := attest.AssertionState{
					AppID:             tt.appID,
					PublicKey:         pubkey,
					OriginalChallenge: tt.stored.Challenge,
					Counter:           tt.stored.Counter,
				}
				got, err := (&attest.AssertionService{}).VerifyWithState(assertionObject, tt.challenge, tt.clientData, state)
				if tt.wantErr != nil {
					if err == nil {
						t.Fatalf("expected error %q, got nil", tt.wantErr)
					}
					if !errors.Is(err, tt.wantErr) && !strings.Contains(err.Error(), tt.wantErr.Error()) {
						t.Fatalf("got error %q, want %q", err, tt.wantErr)
					}
					return
				} else if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if got.Counter != tt.newCounter {
					t.Errorf("invalid new counter want: %d, got: %d", tt.newCounter, got.Counter)
				}
				t.Logf("golden case verified: counter=%d, bundleVersion=%q, validationCategory=%v",
					got.Counter, got.AppleBundleVersion, got.AppleValidationCategory)
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
				if tt.wantErr != nil {
					if err == nil {
						t.Fatalf("expected error %q, got nil", tt.wantErr)
					}
					if !errors.Is(err, tt.wantErr) && !strings.Contains(err.Error(), tt.wantErr.Error()) {
						t.Fatalf("got error %q, want %q", err, tt.wantErr)
					}
					return
				} else if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if got != tt.newCounter {
					t.Errorf("invalid new counter want: %d, got: %d", tt.newCounter, got)
				}
			})
		})
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
