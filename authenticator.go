package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

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

type ValidationCategory uint32

const (
	ValidationCategoryInvalid      ValidationCategory = 0
	ValidationCategoryOSExecutable ValidationCategory = 1
	ValidationCategoryTestFlight   ValidationCategory = 2
	ValidationCategoryDevelopment  ValidationCategory = 3
	ValidationCategoryAppStore     ValidationCategory = 4
	ValidationCategoryEnterprise   ValidationCategory = 5
	ValidationCategoryDeveloperID  ValidationCategory = 6
	ValidationCategoryRestricted7  ValidationCategory = 7
	ValidationCategoryRestricted8  ValidationCategory = 8
	ValidationCategoryRestricted9  ValidationCategory = 9
	ValidationCategoryOther        ValidationCategory = 10
)

func (c ValidationCategory) String() string {
	switch c {
	case ValidationCategoryInvalid:
		return "Invalid"
	case ValidationCategoryOSExecutable:
		return "OS Executable"
	case ValidationCategoryTestFlight:
		return "TestFlight"
	case ValidationCategoryDevelopment:
		return "Development"
	case ValidationCategoryAppStore:
		return "App Store"
	case ValidationCategoryEnterprise:
		return "Enterprise/Ad-hoc"
	case ValidationCategoryDeveloperID:
		return "Developer ID"
	case ValidationCategoryRestricted7, ValidationCategoryRestricted8, ValidationCategoryRestricted9:
		return fmt.Sprintf("Restricted(%d)", uint32(c))
	case ValidationCategoryOther:
		return "Other"
	default:
		return fmt.Sprintf("Unknown(%d)", uint32(c))
	}
}

var ErrUnknownKey = errors.New("authdata: unknown key")

type AuthenticatorData struct {
	RPIDHash                []byte
	Flags                   byte
	Counter                 uint32
	CredentialData          AttestedCredential
	AppleBundleVersion      string `cbor:"apple_bundle_version_01"`
	AppleValidationCategory uint32 `cbor:"apple_validation_category_01"`
}

type AttestedCredential struct {
	AAGUID       []byte
	CredentialID []byte
	CoseKey      CoseKey
}

func (auth *AuthenticatorData) HasAttestedCredentialData() bool {
	return auth.Flags&Attested != 0
}

func (auth *AuthenticatorData) Unmarshal(rawBytes []byte) error {
	if minAuthDataLen > len(rawBytes) {
		return fmt.Errorf("authenticator data length too short: got %d bytes", len(rawBytes))
	}
	r := safeReader{rawBytes: rawBytes}
	rpidHash, err := r.ReadBytes(32)
	if err != nil {
		return fmt.Errorf("failed to read RPIDHash: %w", err)
	}
	auth.RPIDHash = rpidHash
	flag, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read Flags: %w", err)
	}
	auth.Flags = flag
	counter, err := r.ReadUint32()
	if err != nil {
		return fmt.Errorf("failed to read Counter: %w", err)
	}
	auth.Counter = counter

	if auth.HasAttestedCredentialData() {
		if len(rawBytes) > minAuthDataLen {
			aaguid, err := r.ReadBytes(16)
			if err != nil {
				return fmt.Errorf("failed to read AAGUID: %w", err)
			}
			credIDLen, err := r.ReadUint16()
			if err != nil {
				return fmt.Errorf("failed to read credential ID length: %w", err)
			}
			credID, err := r.ReadBytes(int(credIDLen))
			if err != nil {
				return fmt.Errorf("failed to read credential ID: %w", err)
			}

			auth.CredentialData = AttestedCredential{
				AAGUID:       aaguid,
				CredentialID: credID,
			}

			dec := cbor.NewDecoder(r.UnreadBytes())
			auth.CredentialData.CoseKey = CoseKey{}
			if err := auth.CredentialData.CoseKey.UnmarshalCBOR(dec); err != nil {
				return err
			}
			r.Advance(len(r.UnreadBytes()) - dec.Len())
		}
	}
	if r.Len() > 0 {
		dec := cbor.NewDecoder(r.UnreadBytes())
		if err := auth.unmarshalExtensions(dec); err != nil {
			return fmt.Errorf("failed to parse extensions: %w", err)
		}
		r.Advance(len(r.UnreadBytes()) - dec.Len())
	}

	if r.Len() != 0 {
		return fmt.Errorf("unexpected trailing data in authenticator data")
	}

	return nil
}

func (auth *AuthenticatorData) unmarshalExtensions(dec *cbor.Decoder) error {
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
	for i := uint64(0); i < size; i++ {
		mt, ai, err := dec.ReadHeader()
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
		case "apple_bundle_version_01":
			mt, ai, err := dec.ReadHeader()
			if err != nil {
				return fmt.Errorf(`failed to read map value header (key "apple_bundle_version_01") %d: %w`, i, err)
			}
			if mt != cbor.TextString {
				return fmt.Errorf(`expected string for version (key "apple_bundle_version_01"), got major type %d`, mt)
			}
			version, err := dec.ReadTextString(ai)
			if err != nil {
				return fmt.Errorf(`failed to read version (key "apple_bundle_version_01"): %w`, err)
			}
			auth.AppleBundleVersion = version
		case "apple_validation_category_01":
			mt, ai, err := dec.ReadHeader()
			if err != nil {
				return fmt.Errorf(`failed to read map value header (key "apple_validation_category_01") %d: %w`, i, err)
			}
			if mt != cbor.UnsignedInt {
				return fmt.Errorf(`expected integer for category (key "apple_validation_category_01"), got major type %d`, mt)
			}
			category, err := dec.ReadUint32(ai)
			if err != nil {
				return fmt.Errorf(`failed to read category (key "apple_validation_category_01"): %w`, err)
			}
			auth.AppleValidationCategory = category
		default:
			return fmt.Errorf("%w: %s", ErrUnknownKey, key)
		}
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

	for i := range size {
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
			return fmt.Errorf("%w: %d", ErrUnknownKey, key)
		}
	}
	return nil
}

type safeReader struct {
	rawBytes []byte
	offset   int
}

func (r *safeReader) ReadByte() (byte, error) {
	if len(r.rawBytes)-r.offset < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	b := r.rawBytes[r.offset]
	r.offset += 1
	return b, nil
}

func (r *safeReader) ReadBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("invalid length: %d", n)
	}
	if len(r.rawBytes)-r.offset < n {
		return nil, io.ErrUnexpectedEOF
	}
	b := r.rawBytes[r.offset : r.offset+n]
	r.offset += n
	return b, nil
}

func (r *safeReader) ReadUint16() (uint16, error) {
	b, err := r.ReadBytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *safeReader) ReadUint32() (uint32, error) {
	b, err := r.ReadBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (r *safeReader) UnreadBytes() []byte {
	if r.offset >= len(r.rawBytes) {
		return nil
	}
	return r.rawBytes[r.offset:]
}

func (r *safeReader) Advance(pos int) {
	if pos < 0 {
		pos = 0
	}
	r.offset += pos
	if r.offset > len(r.rawBytes) {
		r.offset = len(r.rawBytes)
	}
}

func (r *safeReader) Len() int {
	return len(r.rawBytes) - r.offset
}
