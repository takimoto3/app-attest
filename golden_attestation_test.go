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
	b, err := os.ReadFile("testdata/golden_attestation.json")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("golden case not found: testdata/golden_attestation.json")
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
		return attest.None
	}

	parseTime := func(s string) time.Time {
		if s == "" {
			return time.Time{}
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
		ValidDate            string `json:"validDate"`
		ExpiredDate          string `json:"expiredDate"`
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
		ExpiredDate    time.Time
	}{
		AppID:          raw.TeamIdentifier + "." + raw.BundleIdentifier,
		Attestation:    must(base64.StdEncoding.DecodeString(raw.AttestationBase64)),
		ClientDataHash: must(base64.StdEncoding.DecodeString(raw.ClientDataHashBase64)),
		KeyID:          must(base64.StdEncoding.DecodeString(raw.KeyIDBase64)),
		PublicKey:      block.Bytes,
		Environment:    parseEnvironment(raw.Environment),
		TestDate:       parseTime(raw.ValidDate),
		ExpiredDate:    parseTime(raw.ExpiredDate),
	}

	if fixture.ExpiredDate.IsZero() {
		t.Fatal("expiredDate is missing in golden fixture")
	}
	t.Logf("fixture: %+v\n", fixture)

	tests := map[string]struct {
		TimeNow        time.Time
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
		"Error Case: invalid AppID use": {
			rootCert:       pool,
			appID:          "org.sample.AttestSample",
			attestData:     fixture.Attestation,
			clientDataHash: fixture.ClientDataHash,
			keyID:          fixture.KeyID,
			wantErr:        attest.ErrUnmatchRPIDHash,
		},
		"Error Case:invalid challenge use": {
			rootCert:       pool,
			appID:          fixture.AppID,
			attestData:     fixture.Attestation,
			clientDataHash: []byte("xxxxxxxxxxxxxxxx"),
			keyID:          fixture.KeyID,
			wantErr:        errors.New("credCert extension does not match nonce"),
		},
		"Error Case:invalid keyID use": {
			rootCert:       pool,
			appID:          fixture.AppID,
			attestData:     fixture.Attestation,
			clientDataHash: fixture.ClientDataHash,
			keyID:          must(base64.StdEncoding.DecodeString("vZiLwg6bm6++ogVSpwMVJOfseqKs9mMRQamXExFAR+1=")),
			wantErr:        errors.New("the keyid is not match public key's hash"),
		},
		"Error Case: certificate expired": {
			TimeNow:        fixture.ExpiredDate,
			rootCert:       pool,
			appID:          fixture.AppID,
			attestData:     fixture.Attestation,
			clientDataHash: fixture.ClientDataHash,
			keyID:          fixture.KeyID,
			wantErr:        errors.New("invalid certificate: x509: certificate has expired or is not yet valid"),
		},
		"Error Case: nil root certificate pool": {
			rootCert:       nil,
			appID:          fixture.AppID,
			attestData:     fixture.Attestation,
			clientDataHash: fixture.ClientDataHash,
			keyID:          fixture.KeyID,
			wantErr:        errors.New("root certificate pool is nil"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Set a default valid time for most tests (before certificate expiration)
			if tt.TimeNow.IsZero() {
				testtime.SetTime(t, fixture.TestDate)
			} else {
				testtime.SetTime(t, tt.TimeNow)
			}

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
