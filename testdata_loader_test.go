package attest

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

type Attestation struct {
	ValidDate        time.Time
	ExpiredDate      time.Time
	AppID            string
	Attestation      []byte
	BundleIdentifier string
	ClientDataBase64 string
	ClientDataHash   []byte
	Environment      Environment
	ID               string
	IOSVersion       float64
	KeyId            []byte
	PublicKey        []byte
	TeamIdentifier   string
	Timestamp        time.Time
	Type             string
}

type Assertion struct {
	AppID                      string
	Assertion                  []byte
	BundleIdentifier           string
	Challenge                  []byte
	ClientData                 []byte
	ClientDataHashSha256Base64 string
	Counter                    uint32
	Environment                string
	ID                         string
	KeyIdBase64                string
	PublicKey                  []byte
	TeamIdentifier             string
	Timestamp                  time.Time
	Type                       string
}

type Receipt struct {
	ID               string
	Type             string
	AttestationID    string
	BundleIdentifier string
	Environment      string
	KeyIdBase64      string
	PublicKey        string
	ReceiptBase64    string
	TeamIdentifier   string
	Timestamp        time.Time
	Properties       ReceiptProperties
}

type ReceiptProperties struct {
	ClientHashBase64 string
	CreationTime     time.Time
	Environment      string
	ExpirationTime   time.Time
	NotBefore        time.Time
	RiskMetric       uint32
	Token            string
	Type             string
}

type TestData struct {
	Attestation Attestation
	Assertion   Assertion
	Receipt     []Receipt
}

func (t *TestData) UnmarshalJSON(b []byte) error {
	var tmp struct {
		Attestation struct {
			ValidDate                  string  `json:"validDate"`
			ExpiredDate                string  `json:"expiredDate"`
			AttestationBase64          string  `json:"attestationBase64"`
			BundleIdentifier           string  `json:"bundleIdentifier"`
			ClientDataBase64           string  `json:"clientDataBase64"`
			ClientDataHashSha256Base64 string  `json:"clientDataHashSha256Base64"`
			Environment                string  `json:"environment"`
			ID                         string  `json:"id"`
			IOSVersion                 float64 `json:"iOSVersion"`
			KeyIdBase64                string  `json:"keyIdBase64"`
			PublicKey                  string  `json:"publicKey"`
			TeamIdentifier             string  `json:"teamIdentifier"`
			Timestamp                  string  `json:"timestamp"`
			Type                       string  `json:"type"`
		} `json:"attestation"`
		Assertion struct {
			AssertionBase64            string `json:"assertionBase64"`
			BundleIdentifier           string `json:"bundleIdentifier"`
			ChallengeBase64            string `json:"challengeBase64"`
			ClientDataBase64           string `json:"clientDataBase64"`
			ClientDataHashSha256Base64 string `json:"clientDataHashSha256Base64"`
			Counter                    uint32 `json:"counter"`
			Environment                string `json:"environment"`
			ID                         string `json:"id"`
			KeyIdBase64                string `json:"keyIdBase64"`
			PublicKey                  string `json:"publicKey"`
			TeamIdentifier             string `json:"teamIdentifier"`
			Timestamp                  string `json:"timestamp"`
			Type                       string `json:"type"`
		} `json:"assertion"`
		Receipt []struct {
			ID               string `json:"id"`
			Type             string `json:"type"`
			AttestationID    string `json:"attestationId"`
			BundleIdentifier string `json:"bundleIdentifier"`
			Environment      string `json:"environment"`
			KeyIdBase64      string `json:"keyIdBase64"`
			PublicKey        string `json:"publicKey"`
			ReceiptBase64    string `json:"receiptBase64"`
			TeamIdentifier   string `json:"teamIdentifier"`
			Timestamp        string `json:"timestamp"`
			Properties       struct {
				ClientHashBase64 string `json:"clientHashBase64"`
				CreationTime     string `json:"creationTime"`
				Environment      string `json:"environment"`
				ExpirationTime   string `json:"expirationTime"`
				NotBefore        string `json:"notBefore"`
				RiskMetric       uint32 `json:"riskMetric"`
				Token            string `json:"token"`
				Type             string `json:"type"`
			} `json:"properties"`
		} `json:"receipt"`
	}

	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}

	pemtToDER := func(s string) []byte {
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			panic("invalid PEM data")
		}
		return block.Bytes
	}

	parseTime := func(s string) time.Time {
		if s == "" {
			return time.Time{}
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t, _ = time.Parse(time.RFC3339, s)
		}
		return t
	}

	parseEnvironment := func(s string) Environment {
		switch s {
		case "development", "sandbox":
			return Sandbox
		case "production":
			return Production
		}
		return None
	}

	// Attestation
	t.Attestation = Attestation{
		ValidDate:        parseTime(tmp.Attestation.ValidDate),
		ExpiredDate:      parseTime(tmp.Attestation.ExpiredDate),
		AppID:            fmt.Sprintf("%s.%s", tmp.Attestation.TeamIdentifier, tmp.Attestation.BundleIdentifier),
		Attestation:      DecodeB64(tmp.Attestation.AttestationBase64),
		BundleIdentifier: tmp.Attestation.BundleIdentifier,
		ClientDataBase64: tmp.Attestation.ClientDataBase64,
		ClientDataHash:   DecodeB64(tmp.Attestation.ClientDataHashSha256Base64),
		Environment:      parseEnvironment(tmp.Attestation.Environment),
		ID:               tmp.Attestation.ID,
		IOSVersion:       tmp.Attestation.IOSVersion,
		KeyId:            DecodeB64(tmp.Attestation.KeyIdBase64),
		PublicKey:        pemtToDER(tmp.Attestation.PublicKey),
		TeamIdentifier:   tmp.Attestation.TeamIdentifier,
		Timestamp:        parseTime(tmp.Attestation.Timestamp),
		Type:             tmp.Attestation.Type,
	}

	// Assertion
	t.Assertion = Assertion{
		AppID:                      fmt.Sprintf("%s.%s", tmp.Assertion.TeamIdentifier, tmp.Assertion.BundleIdentifier),
		Assertion:                  DecodeB64(tmp.Assertion.AssertionBase64),
		BundleIdentifier:           tmp.Assertion.BundleIdentifier,
		Challenge:                  DecodeB64(tmp.Assertion.ChallengeBase64),
		ClientData:                 DecodeB64(tmp.Assertion.ClientDataBase64),
		ClientDataHashSha256Base64: tmp.Assertion.ClientDataHashSha256Base64,
		Counter:                    tmp.Assertion.Counter,
		Environment:                tmp.Assertion.Environment,
		ID:                         tmp.Assertion.ID,
		KeyIdBase64:                tmp.Assertion.KeyIdBase64,
		PublicKey:                  pemtToDER(tmp.Assertion.PublicKey),
		TeamIdentifier:             tmp.Assertion.TeamIdentifier,
		Timestamp:                  parseTime(tmp.Assertion.Timestamp),
		Type:                       tmp.Assertion.Type,
	}

	// Receipt
	for _, r := range tmp.Receipt {
		t.Receipt = append(t.Receipt, Receipt{
			ID:               r.ID,
			Type:             r.Type,
			AttestationID:    r.AttestationID,
			BundleIdentifier: r.BundleIdentifier,
			Environment:      r.Environment,
			KeyIdBase64:      r.KeyIdBase64,
			PublicKey:        r.PublicKey,
			ReceiptBase64:    r.ReceiptBase64,
			TeamIdentifier:   r.TeamIdentifier,
			Timestamp:        parseTime(r.Timestamp),
			Properties: ReceiptProperties{
				ClientHashBase64: r.Properties.ClientHashBase64,
				CreationTime:     parseTime(r.Properties.CreationTime),
				Environment:      r.Properties.Environment,
				ExpirationTime:   parseTime(r.Properties.ExpirationTime),
				NotBefore:        parseTime(r.Properties.NotBefore),
				RiskMetric:       r.Properties.RiskMetric,
				Token:            r.Properties.Token,
				Type:             r.Properties.Type,
			},
		})
	}

	return nil
}

func DecodeB64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func LoadTestData(files ...string) (*TestData, error) {
	if len(files) == 0 {
		files = []string{"testdata/attestdata.json", "testdata/ios-14.4.json"}
	}

	var data []byte
	var err error

	for _, file := range files {
		if fileExists(file) {
			data, err = os.ReadFile(file)
			if err != nil {
				return nil, err
			}
			break
		}
	}

	if data == nil {
		return nil, fmt.Errorf("no test data file found among candidates: %v", files)
	}

	var testData TestData
	if err = json.Unmarshal(data, &testData); err != nil {
		return nil, err
	}
	return &testData, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}
