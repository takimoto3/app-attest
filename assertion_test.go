package attest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/pkg/errors"
	attest "github.com/takimoto3/app-attest"
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

	testData, err := loadTestData()
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
			errors.Errorf("invalid challenge expected: %s, received: xxxxxxxxxxxxxxxx", string(testData.Assertion.Challenge)),
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
			errors.Errorf("invalid challenge expected: xxxxxxxxxxxxxxxx, received: %s", string(testData.Assertion.Challenge)),
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
			errors.Errorf("counter was not not greater than previous [1, previous: 3]"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pubany, err := x509.ParsePKIXPublicKey(tt.pubkey)
			if err != nil {
				t.Fatal(err)
			}
			pubkey := pubany.(*ecdsa.PublicKey)

			target := attest.AssertionService{
				AppID:     tt.appID,
				Challenge: tt.stored.Challenge,
				Counter:   uint32(tt.stored.Counter),
				PublicKey: pubkey,
			}

			assertionObject := &attest.AssertionObject{}
			err = assertionObject.Unmarshal(tt.assertData)
			if err != nil {
				t.Fatal(err)
			}
			got, err := target.Verify(assertionObject, tt.challenge, tt.clientData)
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
