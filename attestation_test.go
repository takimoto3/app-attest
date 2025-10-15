package attest_test

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	attest "github.com/takimoto3/app-attest"
	"github.com/tenntenn/testtime"
)

func TestAttestationService_Verify(t *testing.T) {
	testData, err := loadTestData()
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		appID          string
		attestData     []byte
		clientDataHash []byte
		keyID          []byte
		wantErr        error
		wantPubkey     []byte
		wantEnv        attest.Environment
	}{
		"Success Case": {
			testData.Attestation.AppID,
			testData.Attestation.Attestation,
			testData.Attestation.ClientDataHash,
			testData.Attestation.KeyId,
			nil,
			testData.Attestation.PublicKey,
			testData.Attestation.Environment,
		},
		"Error Case: invalid AppID use": {
			"org.sample.AttestSample",
			testData.Attestation.Attestation,
			testData.Attestation.ClientDataHash,
			testData.Attestation.KeyId,
			attest.ErrUnmatchRPIDHash,
			testData.Attestation.PublicKey,
			testData.Attestation.Environment,
		},
		"Error Case:invalid challenge use": {
			testData.Attestation.AppID,
			testData.Attestation.Attestation,
			[]byte("xxxxxxxxxxxxxxxx"),
			testData.Attestation.KeyId,
			errors.New("credCert extension does not match nonce"),
			testData.Attestation.PublicKey,
			testData.Attestation.Environment,
		},
		"Error Case:invalid keyID use": {
			testData.Attestation.AppID,
			testData.Attestation.Attestation,
			testData.Attestation.ClientDataHash,
			decodeB64("vZiLwg6bm6++ogVSpwMVJOfseqKs9mMRQamXExFAR+1="),
			errors.New("the keyid is not match public key's hash"),
			testData.Attestation.PublicKey,
			testData.Attestation.Environment,
		},
		"Error Case: certificate expired": {
			testData.Attestation.AppID,
			testData.Attestation.Attestation,
			testData.Attestation.ClientDataHash,
			testData.Attestation.KeyId,
			errors.New("invalid certificate: x509: certificate has expired or is not yet valid"),
			testData.Attestation.PublicKey,
			testData.Attestation.Environment,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Set a default valid time for most tests (before certificate expiration)
			testtime.SetTime(t, testData.Attestation.ValidDate)
			if strings.HasSuffix(name, "certificate expired") {
				testtime.SetTime(t, testData.Attestation.ExpiredDate)
			}

			target := attest.AttestationService{
				PathForRootCA: "testdata/Apple_App_Attestation_Root_CA.pem",
				AppID:         tt.appID,
			}

			attestObject := attest.AttestationObject{}
			if err := attestObject.Unmarshal(tt.attestData); err != nil {
				t.Fatal(err)
			}

			result, err := target.Verify(&attestObject, tt.clientDataHash, tt.keyID)
			if !IsEquals(tt.wantErr, err) {
				t.Fatal(err)
			}

			if result != nil {
				gotPubkey, err := x509.MarshalPKIXPublicKey(result.PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(tt.wantPubkey, gotPubkey); diff != "" {
					t.Errorf("Mismatch (-want +got):\n%s", diff)
				}
				if tt.wantEnv != result.Environment {
					t.Errorf("invaild enviroment value want: %s, got: %s", tt.wantEnv, result.Environment)
				}
				if len(result.Receipt) == 0 {
					t.Error("no recipe in the result")
				}
				t.Logf("receipt size: %d", len(result.Receipt))
			}
		})
	}
}

func IsEquals(target, err error) bool {
	if target == nil || err == nil {
		return err == target
	}
	if errors.As(err, &target) {
		return true
	}
	return strings.Contains(err.Error(), target.Error())
}
