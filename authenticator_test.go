package attest_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	attest "github.com/takimoto3/app-attest"
)

func TestAuthenticatorData_HasAttestedCredentialData(t *testing.T) {
	tests := []struct {
		name   string
		target *attest.AuthenticatorData
		want   bool
	}{
		{
			"true case",
			&attest.AuthenticatorData{
				Flags: 0x40,
			},
			true,
		},
		{
			"false case",
			&attest.AuthenticatorData{
				Flags: 0x10,
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.target.HasAttestedCredentialData(); tt.want != got {
				t.Errorf("HasAttestedCredentialData() invalid result want %v got:%v", tt.want, got)
			}
		})
	}
}

func TestAuthenticatorData_Unmarshal(t *testing.T) {
	tests := map[string]struct {
		rawString string
		err       error
	}{
		"valid authenticator data": {
			"lWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4/Xy7IpvdRBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQIniszxcGnhupdPFOHJIm6dscrWCC2h8xHicBMu91THD0kdOdB0QQtkaEn+6KfsfT1o3NmmFT8YfXrG734WfVSmlAQIDJiABIVggyoHHeiUw5aSbt8/GsL9zaqZGRzV26A4y3CnCGUhVXu4iWCBMnc8za5xgPzIygngAv9W+vZTMGJwwZcM4sjiqkcb/1g==",
			nil,
		},
		"invalid authenticator data": {
			"pkLSG3xtVeHOI8U5mCjSx0m/am7y/gPMnhDN9O1TCItBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQMAxl6G32ykWaLrv/ouCs5HoGsvONqBtOb7ZmyMs8K8PccnwyyqPzWn/yZuyQmQBguvjYSvH6gDBlFG65quUDCSlAQIDJiABIVggyJGP+ra/u/eVjqN4OeYXUShRWxrEeC6Sb5/bZmJ9q8MiWCCHIkRdg5oRb1RHoFVYUpogcjlObCKFsV1ls1T+uUc6rA==",
			nil,
		},
		"empty authenticator data": {
			"",
			fmt.Errorf("authenticator data length too short: got 0 bytes"),
		},
		"valid authenticator data without attested credential": {
			func() string {
				raw := make([]byte, 37)
				raw[32] = 0x01 // bit0 = User Present, bit6 = AttestedCredentialData なし
				return base64.StdEncoding.EncodeToString(raw)
			}(),
			nil,
		},
		"too short overall": {
			// shorter than minAuthDataLen (37 bytes)
			rawString: base64.StdEncoding.EncodeToString(make([]byte, 20)),
			err:       fmt.Errorf("authenticator data length too short: got 20 bytes"),
		},
		"extra trailing bytes": {
			func() string {
				raw := make([]byte, 37)
				raw = append(raw, make([]byte, 10)...) // unexpected extra data
				return base64.StdEncoding.EncodeToString(raw)
			}(),
			fmt.Errorf("unexpected trailing data in authenticator data"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			auth := &attest.AuthenticatorData{}
			rawBytes, err := base64.StdEncoding.DecodeString(tt.rawString)
			if err != nil {
				t.Error(err)
			}
			err = auth.Unmarshal(rawBytes)
			if tt.err == nil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Errorf("expected error %v, got nil", tt.err)
				return
			}
			if !strings.Contains(err.Error(), tt.err.Error()) {
				t.Errorf("expected error %q, got %q", tt.err.Error(), err.Error())
			}
		})
	}
}
