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

type AssertionResult struct {
	// Counter is the new sign count. Callers must persist it and reject
	// any future assertion whose counter isn't strictly greater.
	Counter uint32

	// AppleBundleVersion is the attested CFBundleVersion. Empty on iOS 26
	// and earlier, which lack this extension.
	AppleBundleVersion string

	// AppleValidationCategory is the attested distribution channel
	// (App Store, TestFlight, Development, etc). Zero value on iOS 26
	// and earlier, which lack this extension.
	AppleValidationCategory ValidationCategory
}

// Verify checks a single assertion object and returns the counter.
//
// Deprecated: Use VerifyWithExtensions instead, which also returns the
// Apple-attested bundle version and validation category extensions
// introduced in iOS 27.
func (service *AssertionService) Verify(assertObject *AssertionObject, challenge string, clientData []byte) (uint32, error) {
	result, err := service.verify(assertObject, challenge, clientData)
	if err != nil {
		return 0, err
	}
	return result.Counter, nil
}

// VerifyWithExtensions checks a single assertion object and returns the
// verification result, including the sign counter and any Apple-attested
// app-version extensions (iOS 27+).
func (service *AssertionService) VerifyWithExtensions(assertObject *AssertionObject, challenge string, clientData []byte) (*AssertionResult, error) {
	return service.verify(assertObject, challenge, clientData)
}

func (service *AssertionService) verify(assertObject *AssertionObject, challenge string, clientData []byte) (*AssertionResult, error) {
	// 1. Compute clientDataHash as the SHA256 hash of clientData.
	clientDataHash := sha256.Sum256(clientData)

	// 2. Concatenate authenticatorData and clientDataHash, and apply a SHA256 hash over the result to form nonce.
	hash := sha256.New()
	hash.Write(assertObject.AuthData)
	hash.Write(clientDataHash[:])
	nonce := hash.Sum(nil)

	// 3. Use the public key that you store from the attestation object to verify that the assertion’s signature is valid for nonce.
	nonceHash := sha256.Sum256(nonce[:])
	if ok := ecdsa.VerifyASN1(service.PublicKey, nonceHash[:], assertObject.Signature); !ok {
		return nil, ErrInvalidSignature
	}

	// 4. Compute the SHA256 hash of the client’s App ID, and verify that it matches the RP ID in the authenticator data.
	authData := AuthenticatorData{}
	if err := authData.Unmarshal(assertObject.AuthData); err != nil {
		return nil, fmt.Errorf("authenticator data decoding failed: %w", err)
	}
	appIDHash := sha256.Sum256([]byte(service.AppID))
	if !bytes.Equal(authData.RPIDHash[:], appIDHash[:]) {
		return nil, ErrUnmatchRPIDHash
	}

	// 5. Verify that the authenticator data’s counter value is greater than the value from the previous assertion, or greater than 0 on the first assertion.
	if authData.Counter <= service.Counter {
		return nil, fmt.Errorf("counter was not not greater than previous [%d, previous: %d]", authData.Counter, service.Counter)
	}

	// 6. Verify that the embedded challenge in the client data matches the earlier challenge to the client.
	if challenge != service.Challenge {
		return nil, fmt.Errorf("invalid challenge expected: %s, received: %s", service.Challenge, challenge)
	}

	return &AssertionResult{
		Counter:                 authData.Counter,
		AppleBundleVersion:      authData.AppleBundleVersion,
		AppleValidationCategory: ValidationCategory(authData.AppleValidationCategory),
	}, nil
}

// UnmarshalCBOR decodes the CBOR-encoded data into the AssertionObject.
//
// Returns an error if the data is malformed or contains unexpected types.
func (ao *AssertionObject) UnmarshalCBOR(data []byte) error {
	dec := cbor.NewDecoder(data)
	mt, ai, err := dec.ReadHeader()
	if err != nil {
		return fmt.Errorf("failed to read CBOR map header: %w", err)
	}
	if mt != cbor.Map {
		return fmt.Errorf("expected CBOR type Map (major type 5) for AssertionObject, got major type %d", mt)
	}
	size, err := dec.ReadAdditional(ai)
	if err != nil {
		return fmt.Errorf("failed to read CBOR map size: %w", err)
	}
	for i := range size {
		mt, ai, err = dec.ReadHeader()
		if err != nil {
			return fmt.Errorf("failed to read map key header at index %d: %w", i, err)
		}
		if mt != cbor.TextString {
			return fmt.Errorf("expected string map key at index %d, got major type %d", i, mt)
		}
		key, err := dec.ReadUnsafeTextString(ai)
		if err != nil {
			return fmt.Errorf("failed to read map key string at index %d: %w", i, err)
		}
		switch key {
		case "signature":
			mt, ai, err = dec.ReadHeader()
			if err != nil {
				return fmt.Errorf(`failed to read map value header (key "signature") at index %d: %w`, i, err)
			}
			if mt != cbor.ByteString {
				return fmt.Errorf(`expected bytestring for signature (key "signature"), got major type %d`, mt)
			}
			val, err := dec.ReadByteString(ai)
			if err != nil {
				return fmt.Errorf(`failed to read signature bytes (key "signature"): %w`, err)
			}
			ao.Signature = val
		case "authenticatorData":
			mt, ai, err = dec.ReadHeader()
			if err != nil {
				return fmt.Errorf(`failed to read map value header (key "authenticatorData") at index %d: %w`, i, err)
			}
			if mt != cbor.ByteString {
				return fmt.Errorf(`expected bytestring for authData (key "authenticatorData"), got major type %d`, mt)
			}
			val, err := dec.ReadByteString(ai)
			if err != nil {
				return fmt.Errorf(`failed to read authData bytes (key "authenticatorData"): %w`, err)
			}
			ao.AuthData = val
		default:
			return fmt.Errorf("%w: %s", ErrUnknownKey, key)
		}
	}
	return nil
}
