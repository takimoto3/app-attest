package receipt_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/takimoto3/app-attest/certs"
	"github.com/takimoto3/app-attest/fraud/receipt"
	"github.com/tenntenn/testtime"
)

func TestGolden_ReceiptVerifier_Verify(t *testing.T) {
	b, err := os.ReadFile("testdata/golden_receipt.json")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("golden case not found: testdata/golden_receipt.json")
	}
	if err != nil {
		t.Fatal(err)
	}

	parseTime := func(s string) time.Time {
		if s == "" {
			return time.Time{}
		}
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return tm
	}

	must := func(data []byte, err error) []byte {
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	parsePubKey := func(s string) *ecdsa.PublicKey {
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			t.Fatal("invalid PEM format in publicKeyPEM")
		}
		pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		ecPubKey, ok := pubkey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("unexpected key type %T (want *ecdsa.PublicKey)", pubkey)

		}
		return ecPubKey
	}

	type raw struct {
		Type             string `json:"type"`
		BundleIdentifier string `json:"bundleIdentifier"`
		TeamIdentifier   string `json:"teamIdentifier"`
		PublicKeyPEM     string `json:"publicKeyPEM"` // PEM
		ReceiptBase64    string `json:"receiptBase64"`
		Properties       struct {
			Type           string `json:"type"`
			CreationTime   string `json:"creationTime"`
			NotBefore      string `json:"notBefore"`
			ExpirationTime string `json:"expirationTime"`
			RiskMetric     uint32 `json:"riskMetric"`
		} `json:"properties"`
	}
	var file struct {
		Raw []raw `json:"receipt"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	rawList := file.Raw

	type Fixture struct {
		Type        string
		AppID       string
		PublicKey   *ecdsa.PublicKey
		ReceiptData []byte
		Properties  struct {
			Type           string
			CreationTime   time.Time
			NotBefore      time.Time
			ExpirationTime time.Time
			RiskMetric     int
		}
	}
	fixtures := make([]Fixture, 0, len(rawList))
	for _, raw := range rawList {
		fixture := Fixture{
			Type:        raw.Type,
			AppID:       raw.TeamIdentifier + "." + raw.BundleIdentifier,
			PublicKey:   parsePubKey(raw.PublicKeyPEM),
			ReceiptData: must(base64.StdEncoding.DecodeString(raw.ReceiptBase64)),
			Properties: struct {
				Type           string
				CreationTime   time.Time
				NotBefore      time.Time
				ExpirationTime time.Time
				RiskMetric     int
			}{
				Type:           raw.Properties.Type,
				CreationTime:   parseTime(raw.Properties.CreationTime),
				NotBefore:      parseTime(raw.Properties.NotBefore),
				ExpirationTime: parseTime(raw.Properties.ExpirationTime),
				RiskMetric:     int(raw.Properties.RiskMetric),
			},
		}

		fixtures = append(fixtures, fixture)
	}

	pool, err := certs.LoadCertFiles("testdata/AppleRootCA-G3.cer")
	if err != nil {
		t.Fatal(err)
	}
	verifier := receipt.NewReceiptVerifier(pool)

	for _, f := range fixtures {
		t.Run(f.Type, func(t *testing.T) {
			// Anchor "now" to just after this receipt's creation time so
			// it falls within 5 minutes, regardless of when the test runs.
			testtime.SetTime(t, f.Properties.CreationTime.Add(time.Minute))

			got, err := verifier.Verify(f.ReceiptData, f.AppID, f.PublicKey)
			if err != nil {
				t.Fatalf("Verify() failed: %v", err)
			}
			if got == nil {
				t.Fatal("receipt is nil")
			}

			want := &receipt.Receipt{
				AppID:          f.AppID,
				Type:           f.Properties.Type,
				CreationTime:   f.Properties.CreationTime,
				NotBefore:      f.Properties.NotBefore,
				ExpirationTime: f.Properties.ExpirationTime,
				RiskMetric:     int(f.Properties.RiskMetric),
			}

			opts := cmpopts.IgnoreFields(receipt.Receipt{}, "PublicKey", "Unknown", "MaxAge")
			if diff := cmp.Diff(want, got, opts); diff != "" {
				t.Errorf("Mismatch (-want +got):\n%s", diff)
			}

			if err := got.Validate(f.AppID, f.PublicKey); err != nil {
				t.Fatalf("Validate() failed: %v", err)
			}

			t.Logf("\n--- [RECEIVED RECEIPT] ---\n%s--------------------------", logReceipt(got))
		})
	}
}
