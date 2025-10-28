package attest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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
			fmt.Errorf("counter was not not greater than previous [1, previous: 3]"),
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
			err = assertionObject.UnmarshalCBOR(tt.assertData)
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

	for i := 0; i < b.N; i++ {
		var ao attest.AssertionObject
		if err := ao.UnmarshalCBOR(data); err != nil {
			b.Fatal(err)
		}
	}
}
