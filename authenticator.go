package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"

	"github.com/takimoto3/app-attest/cbor"
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
	AAGUID                  []byte
	CredentialID            []byte
	CoseKey                 CoseKey
	AppleBundleVersion      string `cbor:"apple_bundle_version_01"`
	AppleValidationCategory uint32 `cbor:"apple_validation_category_01"`
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
			auth.CredentialData = AttestedCredential{}
			auth.CredentialData.AAGUID = rawBytes[37:53]
			credIDLen := binary.BigEndian.Uint16(rawBytes[53:55])
			auth.CredentialData.CredentialID = rawBytes[55 : 55+credIDLen]
			rest := rawBytes[55+credIDLen:]
			dec := cbor.NewDecoder(rest)
			auth.CredentialData.CoseKey = CoseKey{}
			err := auth.CredentialData.CoseKey.UnmarshalCBOR(dec)
			if err != nil {
				return err
			}
			remain = dec.Len()
		}
	}
	if remain != 0 {
		return fmt.Errorf("unexpected trailing data in authenticator data")
	}

	return nil
}

type CoseKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

func (k *CoseKey) ParsePublicKey() (*ecdsa.PublicKey, error) {
	if len(k.X) != 32 || len(k.Y) != 32 {
		return nil, fmt.Errorf("invalid coordinate length: X len=%d, Y len=%d (expected 32 bytes each)", len(k.X), len(k.Y))
	}

	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	copy(uncompressed[1:33], k.X)
	copy(uncompressed[33:65], k.Y)

	pubKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, fmt.Errorf("failed to parse uncompressed EC public key: %w", err)
	}
	return pubKey, nil
}

func (k *CoseKey) UnmarshalCBOR(dec *cbor.Decoder) error {
	mt, ai, err := dec.ReadHeader()
	if err != nil {
		return fmt.Errorf("failed to read CBOR map header: %w", err)
	}

	if mt != cbor.Map {
		return fmt.Errorf("expected CBOR type Map (major type 5), got major type %d", mt)
	}

	size, err := dec.ReadAdditional(ai)
	if err != nil {
		return fmt.Errorf("failed to read CBOR map size: %w", err)
	}

	for i := 0; i < int(size); i++ {
		mt, ai, err := dec.ReadHeader()
		if err != nil {
			return fmt.Errorf("failed to read map key header at index %d: %w", i, err)
		}
		if mt != cbor.UnsignedInt && mt != cbor.NegativeInt {
			return fmt.Errorf("expected integer map key at index %d, got major type %d", i, mt)
		}

		key, err := dec.ReadInt(mt, ai)
		if err != nil {
			return fmt.Errorf("failed to parse map key integer at index %d: %w", i, err)
		}

		switch key {
		case 1: // Kty
			mt, ai, err := dec.ReadHeader()
			if err != nil {
				return fmt.Errorf("failed to read Kty header (key 1): %w", err)
			}
			if mt != cbor.UnsignedInt && mt != cbor.NegativeInt {
				return fmt.Errorf("expected integer for Kty (key 1), got major type %d", mt)
			}
			val, err := dec.ReadInt(mt, ai)
			if err != nil {
				return fmt.Errorf("failed to read Kty value: %w", err)
			}
			k.Kty = int(val)

		case 3: // Alg
			mt, ai, err := dec.ReadHeader()
			if err != nil {
				return fmt.Errorf("failed to read Alg header (key 3): %w", err)
			}
			if mt != cbor.UnsignedInt && mt != cbor.NegativeInt {
				return fmt.Errorf("expected integer for Alg (key 3), got major type %d", mt)
			}
			val, err := dec.ReadInt(mt, ai)
			if err != nil {
				return fmt.Errorf("failed to read Alg value: %w", err)
			}
			k.Alg = int(val)

		case -1: // Crv
			mt, ai, err := dec.ReadHeader()
			if err != nil {
				return fmt.Errorf("failed to read Crv header (key -1): %w", err)
			}
			if mt != cbor.UnsignedInt && mt != cbor.NegativeInt {
				return fmt.Errorf("expected integer for Crv (key -1), got major type %d", mt)
			}
			val, err := dec.ReadInt(mt, ai)
			if err != nil {
				return fmt.Errorf("failed to read Crv value: %w", err)
			}
			k.Crv = int(val)

		case -2: // X coordinate
			mt, ai, err := dec.ReadHeader()
			if err != nil {
				return fmt.Errorf("failed to read X coordinate header (key -2): %w", err)
			}
			if mt != cbor.ByteString {
				return fmt.Errorf("expected ByteString for X coordinate (key -2), got major type %d", mt)
			}
			val, err := dec.ReadByteString(ai)
			if err != nil {
				return fmt.Errorf("failed to read X coordinate bytes: %w", err)
			}
			k.X = val

		case -3: // Y coordinate
			mt, ai, err := dec.ReadHeader()
			if err != nil {
				return fmt.Errorf("failed to read Y coordinate header (key -3): %w", err)
			}
			if mt != cbor.ByteString {
				return fmt.Errorf("expected ByteString for Y coordinate (key -3), got major type %d", mt)
			}
			val, err := dec.ReadByteString(ai)
			if err != nil {
				return fmt.Errorf("failed to read Y coordinate bytes: %w", err)
			}
			k.Y = val

		default:
		}
	}
	return nil
}
