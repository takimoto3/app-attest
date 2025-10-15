package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"

	cbor "github.com/brianolson/cbor_go"
)

var (
	ErrInvalidSignature = errors.New("invalid the assertion signature")
	ErrUnmatchRPIDHash  = errors.New("RP Hash mismatch")
)

type AssertionObject struct {
	// ASN.1 Encoded as a Sequence of two integers
	Signature []byte `cbor:"signature"`
	AuthData  []byte `cbor:"authenticatorData"`
}

func (obj *AssertionObject) Unmarshal(rawBytes []byte) error {
	dec := cbor.NewDecoder(bytes.NewReader(rawBytes))
	return dec.Decode(obj)
}

type AssertionService struct {
	AppID     string
	Challenge string
	PublicKey *ecdsa.PublicKey
	Counter   uint32
}

func (service *AssertionService) Verify(assertObject *AssertionObject, challenge string, clientData []byte) (uint32, error) {
	// 1. Compute clientDataHash as the SHA256 hash of clientData.
	clientDataHash := sha256.Sum256(clientData)

	// 2. Concatenate authenticatorData and clientDataHash, and apply a SHA256 hash over the result to form nonce.
	nonce := sha256.Sum256(append(assertObject.AuthData, clientDataHash[:]...))

	// 3. Use the public key that you store from the attestation object to verify that the assertion’s signature is valid for nonce.
	nonceHash := sha256.Sum256(nonce[:])
	if ok := ecdsa.VerifyASN1(service.PublicKey, nonceHash[:], assertObject.Signature); !ok {
		return 0, ErrInvalidSignature
	}

	// 4. Compute the SHA256 hash of the client’s App ID, and verify that it matches the RP ID in the authenticator data.
	authData := AuthenticatorData{}
	if err := authData.Unmarshal(assertObject.AuthData); err != nil {
		return 0, fmt.Errorf("authenticator data decoding failed: %w", err)
	}
	appIDHash := sha256.Sum256([]byte(service.AppID))
	if !bytes.Equal(authData.RPIDHash[:], appIDHash[:]) {
		return 0, ErrUnmatchRPIDHash
	}

	// 5. Verify that the authenticator data’s counter value is greater than the value from the previous assertion, or greater than 0 on the first assertion.
	if authData.Counter <= service.Counter {
		return 0, fmt.Errorf("counter was not not greater than previous [%d, previous: %d]", authData.Counter, service.Counter)
	}

	// 6. Verify that the embedded challenge in the client data matches the earlier challenge to the client.
	if challenge != service.Challenge {
		return 0, fmt.Errorf("invalid challenge expected: %s, received: %s", service.Challenge, challenge)
	}

	return authData.Counter, nil
}
