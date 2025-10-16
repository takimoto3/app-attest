package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/takimoto3/app-attest/cbor"
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

type AssertionService struct {
	AppID     string
	Challenge string
	PublicKey *ecdsa.PublicKey
	Counter   uint32
}

// Verify checks a single assertion object and returns the counter.
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

// UnmarshalCBOR decodes the CBOR-encoded data into the AssertionObject.
//
// Returns an error if the data is malformed or contains unexpected types.
func (ao *AssertionObject) UnmarshalCBOR(data []byte) error {
	dec := cbor.NewDecoder(data)
	mt, ai, err := dec.ReadHeader()
	if err != nil {
		return err
	}
	if mt != cbor.Map {
		return fmt.Errorf("cbor: expected map for AssertionObject got %v", mt)
	}
	size, err := dec.ReadAdditional(ai)
	if err != nil {
		return err
	}
	for i := 0; i < int(size); i++ {
		mt, ai, err := dec.ReadHeader()
		if err != nil {
			return err
		}
		if mt != cbor.TextString {
			return fmt.Errorf("cbor: expected textstring for map key got %v", mt)
		}
		key, err := dec.ReadTextString(ai)
		if err != nil {
			return err
		}
		switch key {
		case "signature":
			mt, ai, err = dec.ReadHeader()
			if err != nil {
				return err
			}
			if mt != cbor.ByteString {
				return fmt.Errorf("cbor: expected bytestring for \"signature\", got %v", mt)
			}
			val, err := dec.ReadByteString(ai)
			if err != nil {
				return err
			}
			ao.Signature = val
		case "authenticatorData":
			mt, ai, err = dec.ReadHeader()
			if err != nil {
				return err
			}
			if mt != cbor.ByteString {
				return fmt.Errorf("cbor: expected bytestring for \"authenticatorData\", got %v", mt)
			}
			val, err := dec.ReadByteString(ai)
			if err != nil {
				return err
			}
			ao.AuthData = val
		}
	}
	return nil
}
