package attest

import (
	"encoding/binary"

	"github.com/pkg/errors"
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
	var includeCredential byte = 1 << 6
	return (auth.Flags & includeCredential) == includeCredential
}

func (auth *AuthenticatorData) Unmarshal(rawBytes []byte) error {
	if minAuthDataLen > len(rawBytes) {
		return errors.Errorf("authenticator data length too short: got %d bytes", len(rawBytes))
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
		return errors.Errorf("decode authenticator data size incorrect")
	}

	return nil
}
