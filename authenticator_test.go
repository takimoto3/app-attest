package attest_test

import (
	"encoding/base64"
	"fmt"
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
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			auth := &attest.AuthenticatorData{}
			rawBytes, err := base64.StdEncoding.DecodeString(tt.rawString)
			if err != nil {
				t.Error(err)
			}
			if err = auth.Unmarshal(rawBytes); err != tt.err {
				if tt.err != nil && err.Error() == tt.err.Error() {
				} else {
					t.Error(err)
				}
			}
		})
	}
}
