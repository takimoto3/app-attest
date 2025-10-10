package attest_test

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"
	"testing"

	attest "github.com/takimoto3/app-attest"
)

type TestData struct {
	AppID       string
	KeyID       string
	Attestation string
	Publickey   string
	Assertion   string
}

//---
var attestationChallenge = "l5YkqI0Md8fmcBkw"
var assertionChallenge = "bBjeLwdQD4KYRpzL"
var requestBody = "{\"levelId\":\"1234\",\"action\":\"getGameLevel\",\"challenge\":\"bBjeLwdQD4KYRpzL\"}"

func TestAttestationService_Verify(t *testing.T) {
	testData, err := loadTestData("testdata/attestdata.json")
	if err != nil {
		t.Fatal(err)
	}
	expiredData, err := loadTestData("testdata/attestdata_expired.json")
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		appID        string
		attestObject string
		challenge    string
		keyID        string
		wantErr      error
		wantPubkey   string
		wantEnv      attest.Environment
	}{
		"success case": {
			testData.AppID,
			testData.Attestation,
			attestationChallenge,
			testData.KeyID,
			nil,
			testData.Publickey,
			attest.Development,
		},
		"error case(invalid AppID)": {
			"org.sample.AttestSample",
			testData.Attestation,
			attestationChallenge,
			testData.KeyID,
			attest.ErrUnmatchRPIDHash,
			testData.Publickey,
			attest.Development,
		},
		"error case(invalid challenge)": {
			testData.AppID,
			testData.Attestation,
			"xxxxxxxxxxxxxxxx",
			testData.KeyID,
			errors.New("credCert extension does not match nonce"),
			testData.Publickey,
			attest.Development,
		},
		"error case(invalid keyID)": {
			testData.AppID,
			testData.Attestation,
			attestationChallenge,
			"vZiLwg6bm6++ogVSpwMVJOfseqKs9mMRQamXExFAR+1=",
			errors.New("the keyid is not match public key's hash"),
			testData.Publickey,
			attest.Development,
		},
		"error case(certificate expired)": {
			testData.AppID,
			expiredData.Attestation,
			attestationChallenge,
			expiredData.KeyID,
			errors.New("invalid certificate: x509: certificate has expired or is not yet valid"),
			expiredData.Publickey,
			attest.None,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			target := attest.AttestationService{
				PathForRootCA: "testdata/Apple_App_Attestation_Root_CA.pem",
				AppID:         tt.appID,
			}

			attestObject := attest.AttestationObject{}
			rawBytes, err := base64.StdEncoding.DecodeString(tt.attestObject)
			if err != nil {
				t.Fatal(err)
			}
			if err := attestObject.Unmarshal(rawBytes); err != nil {
				t.Fatal(err)
			}

			clientData, err := base64.StdEncoding.DecodeString(tt.challenge)
			if err != nil {
				t.Fatal(err)
			}
			clientDataHash := sha256.Sum256(clientData)
			keyID, err := base64.StdEncoding.DecodeString(tt.keyID)
			if err != nil {
				t.Fatal(err)
			}

			result, err := target.Verify(&attestObject, clientDataHash[:], keyID)
			if !IsEquals(tt.wantErr, err) {
				t.Fatal(err)
			}

			if result != nil {
				pubkey := elliptic.Marshal(result.PublicKey.Curve, result.PublicKey.X, result.PublicKey.Y)
				t.Logf("pubkey: [%s]", hex.EncodeToString(pubkey))
				if len(pubkey) != 65 {
					t.Errorf("invalid public key got length: %d", len(pubkey))
				}

				gotPubkey := strings.Replace(hex.EncodeToString(pubkey), "04", "", 1) // "04" uncompressed point
				if tt.wantPubkey != gotPubkey {
					t.Errorf("invalid public key. want:%s, got:%s", tt.wantPubkey, gotPubkey)
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

func loadTestData(path string) (*TestData, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var testData TestData
	if err := json.Unmarshal(bytes, &testData); err != nil {
		return nil, err
	}
	return &testData, nil
}

func IsEquals(err, target error) bool {
	if target == nil || err == nil {
		return err == target
	}
	return err.Error() == target.Error()
}
