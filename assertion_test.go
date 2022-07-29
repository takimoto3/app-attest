package attest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/pkg/errors"
	attest "github.com/takimoto3/app-attest"
)

type StoredData struct {
	Challenge string
	Counter   uint32
}

func TestAssertionService_Verify(t *testing.T) {
	testData, err := loadTestData("testdata/attestdata.json")
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		appID        string
		assertObject string
		clientData   string
		challenge    string
		stored       StoredData
		newCounter   uint32
		pubkey       string
		wantErr      error
	}{
		"success case": {
			testData.AppID,
			testData.Assertion,
			requestBody,
			assertionChallenge,
			StoredData{
				Challenge: assertionChallenge,
				Counter:   0,
			},
			1,
			"04" + testData.Publickey, // "04" uncompressed point
			nil,
		},
		"error case(different public key)": {
			testData.AppID,
			testData.Assertion,
			requestBody,
			assertionChallenge,
			StoredData{
				Challenge: assertionChallenge,
				Counter:   0,
			},
			1,
			"0437c404fa2bbf8fbcf4ee7080573d5fa80c4f6cc3a22f7db43af92c394e7cd1c880c95ab422972625e8e673af1bda2b096654e9b602895601f925bb5941c53082",
			attest.ErrInvalidSignature,
		},
		"error case(empty request body)": {
			testData.AppID,
			testData.Assertion,
			"",
			assertionChallenge,
			StoredData{
				Challenge: assertionChallenge,
				Counter:   0,
			},
			0,
			"04" + testData.Publickey,
			attest.ErrInvalidSignature,
		},
		"error case(client data contains invalid challenge)": {
			testData.AppID,
			testData.Assertion,
			strings.Replace(requestBody, assertionChallenge, "xxxxxxxxxxxxxxxx", 1),
			assertionChallenge,
			StoredData{
				Challenge: assertionChallenge,
				Counter:   0,
			},
			0,
			"04" + testData.Publickey,
			attest.ErrInvalidSignature,
		},
		"error case(invalid challenge)": {
			testData.AppID,
			testData.Assertion,
			requestBody,
			"xxxxxxxxxxxxxxxx",
			StoredData{
				Challenge: assertionChallenge,
				Counter:   0,
			},
			1,
			"04" + testData.Publickey,
			errors.Errorf("invalid challenge expected: %s, received: xxxxxxxxxxxxxxxx", assertionChallenge),
		},
		"error case(invalid stored challenge)": {
			testData.AppID,
			testData.Assertion,
			requestBody,
			assertionChallenge,
			StoredData{
				Challenge: "xxxxxxxxxxxxxxxx",
				Counter:   0,
			},
			1,
			"04" + testData.Publickey,
			errors.Errorf("invalid challenge expected: xxxxxxxxxxxxxxxx, received: %s", assertionChallenge),
		},
		"error case(invalid AppID)": {
			"org.sample.AttestSample",
			testData.Assertion,
			requestBody,
			assertionChallenge,
			StoredData{
				Challenge: assertionChallenge,
				Counter:   0,
			},
			1,
			"04" + testData.Publickey,
			attest.ErrUnmatchRPIDHash,
		},
		"error case(lower counter)": {
			testData.AppID,
			testData.Assertion,
			requestBody,
			assertionChallenge,
			StoredData{
				Challenge: assertionChallenge,
				Counter:   3,
			},
			1,
			"04" + testData.Publickey,
			errors.Errorf("counter was not not greater than previous [1, previous: 3]"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pubkeyBytes, err := hex.DecodeString(tt.pubkey)
			if err != nil {
				t.Fatal(err)
			}
			x, y := elliptic.Unmarshal(elliptic.P256(), pubkeyBytes)
			target := attest.AssertionService{
				AppID:     tt.appID,
				Challenge: tt.stored.Challenge,
				Counter:   uint32(tt.stored.Counter),
				PublicKey: &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
			}

			rawBytes, err := base64.StdEncoding.DecodeString(tt.assertObject)
			if err != nil {
				t.Fatal(err)
			}

			assertionObject := &attest.AssertionObject{}
			err = assertionObject.Unmarshal(rawBytes)
			if err != nil {
				t.Fatal(err)
			}
			got, err := target.Verify(assertionObject, tt.challenge, []byte(tt.clientData))
			if !IsEquals(tt.wantErr, err) {
				t.Fatal(err)
			}
			if err == nil {
				if tt.newCounter != got {
					t.Errorf("invalid new counter want: %d, got: %d", tt.newCounter, got)
				}
			}
		})
	}
}
