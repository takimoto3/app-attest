package attest_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	attest "github.com/takimoto3/app-attest"
	"github.com/takimoto3/app-attest/certs"
	"github.com/tenntenn/testtime"
)

func TestGolden_AttestationService_Verify(t *testing.T) {
	filepath := "testdata/golden_attestation.json"
	b, err := os.ReadFile(filepath)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skipf("golden case not found: %s", filepath)
	}
	if err != nil {
		t.Fatal(err)
	}

	parseEnvironment := func(s string) attest.Environment {
		switch s {
		case "development", "sandbox":
			return attest.Sandbox
		case "production":
			return attest.Production
		}
		t.Fatalf("invalid environment %q in golden fixture", s)
		return attest.None
	}

	parseTime := func(s string) time.Time {
		if s == "" {
			t.Fatalf("testDate is empty in golden fixture")
		}
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatalf("invalid time %q: %v", s, err)
		}
		return tm
	}

	pool, err := certs.LoadCertFiles("testdata/Apple_App_Attestation_Root_CA.pem")
	if err != nil {
		t.Fatal(err)
	}

	var raw struct {
		TeamIdentifier       string `json:"teamIdentifier"`
		BundleIdentifier     string `json:"bundleIdentifier"`
		AttestationBase64    string `json:"attestationBase64"`
		ClientDataHashBase64 string `json:"clientDataHashSha256Base64"`
		KeyIDBase64          string `json:"keyIdBase64"`
		PublicKeyPEM         string `json:"publicKeyPEM"`
		Environment          string `json:"environment"`
		TestDate             string `json:"testDate"`
	}

	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode([]byte(raw.PublicKeyPEM))
	if block == nil {
		t.Fatal("invalid PEM in publicKey")
	}

	fixture := struct {
		AppID          string
		Attestation    []byte
		ClientDataHash []byte
		KeyID          []byte
		PublicKey      []byte
		Environment    attest.Environment
		TestDate       time.Time
	}{
		AppID:          raw.TeamIdentifier + "." + raw.BundleIdentifier,
		Attestation:    must(base64.StdEncoding.DecodeString(raw.AttestationBase64)),
		ClientDataHash: must(base64.StdEncoding.DecodeString(raw.ClientDataHashBase64)),
		KeyID:          must(base64.StdEncoding.DecodeString(raw.KeyIDBase64)),
		PublicKey:      block.Bytes,
		Environment:    parseEnvironment(raw.Environment),
		TestDate:       parseTime(raw.TestDate),
	}

	//	t.Logf("fixture: %+v\n", fixture)

	tests := map[string]struct {
		rootCert       *x509.CertPool
		appID          string
		attestData     []byte
		clientDataHash []byte
		keyID          []byte
		wantErr        error
		wantPubkey     []byte
		wantEnv        attest.Environment
	}{
		"Success Case": {
			rootCert:       pool,
			appID:          fixture.AppID,
			attestData:     fixture.Attestation,
			clientDataHash: fixture.ClientDataHash,
			keyID:          fixture.KeyID,
			wantPubkey:     fixture.PublicKey,
			wantEnv:        fixture.Environment,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Set a default valid time for most tests (before certificate expiration)
			testtime.SetTime(t, fixture.TestDate)

			target := attest.AttestationService{RootCertPool: tt.rootCert}

			attestObject := attest.AttestationObject{}
			if err := attestObject.UnmarshalCBOR(tt.attestData); err != nil {
				t.Fatalf("decode attestation object: %v", err)
			}

			result, err := target.VerifyForiOS(&attestObject, tt.appID, tt.clientDataHash, tt.keyID)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) && !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Fatalf("got error %q, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("Verify returned nil result without error")
			}

			gotPubkey, err := x509.MarshalPKIXPublicKey(result.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.wantPubkey, gotPubkey); diff != "" {
				t.Errorf("Mismatch (-want +got):\n%s", diff)
			}
			if tt.wantEnv != result.Environment {
				t.Errorf("invalid environment value want: %s, got: %s", tt.wantEnv, result.Environment)
			}
			if len(result.Receipt) == 0 {
				t.Error("no receipt in the result")
			}
			t.Logf("receipt size: %d", len(result.Receipt))
		})
	}
}
