package attest

import (
	"encoding/binary"
	"fmt"
)

// https://www.w3.org/TR/webauthn-2/#flags
const (
	//	UserPresent  byte = 1 << 0 // bit0: User Present (UP)
	//	UserVerified byte = 1 << 2 // bit2: User Verified (UV)
	Attested byte = 1 << 6 // bit6: Attested credential data included (AT)
// Extensions   byte = 1 << 7 // bit7: Extension data included (ED)
)

const minAuthDataLen = 37

type AuthenticatorData struct {
	RPIDHash       []byte
	Flags          byte
	Counter        uint32
	CredentialData AttestedCredential
}

type AttestedCredential struct {
	AAGUID       []byte
	CredentialID []byte
	// The raw credential public key bytes received from the attestation data
	CredentialPublicKey []byte
}

func (auth *AuthenticatorData) HasAttestedCredentialData() bool {
	return auth.Flags&Attested != 0
}

func (auth *AuthenticatorData) Unmarshal(rawBytes []byte) error {
	if minAuthDataLen > len(rawBytes) {
		return fmt.Errorf("authenticator data length too short: got %d bytes", len(rawBytes))
	}
	auth.RPIDHash = rawBytes[:32]
	auth.Flags = rawBytes[32]
	auth.Counter = binary.BigEndian.Uint32(rawBytes[33:37])

	remain := len(rawBytes) - minAuthDataLen

	if auth.HasAttestedCredentialData() {
		if len(rawBytes) > minAuthDataLen {
			cred := AttestedCredential{}
			cred.AAGUID = rawBytes[37:53]
			credIDLen := binary.BigEndian.Uint16(rawBytes[53:55])
			cred.CredentialID = rawBytes[55 : 55+credIDLen]
			cred.CredentialPublicKey = rawBytes[55+credIDLen:]
			auth.CredentialData = cred

			remain = remain - (len(cred.AAGUID) + 2 + len(cred.CredentialID) + len(cred.CredentialPublicKey))
		}
	}
	if remain != 0 {
		return fmt.Errorf("unexpected trailing data in authenticator data")
	}

	return nil
}
