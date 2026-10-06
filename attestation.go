package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"

	"github.com/takimoto3/app-attest/cbor"
)

const maxX5CCerts = 8

// expectedACL is the expected access policy hash (aclBlob) for macOS App Attest keys
// under SIP and Full Security mode (OID 1.2.840.113635.100.8.6).
//
// Ref: https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
var expectedACL = []byte{0x30, 0x40, 0xc, 0x2, 0x31, 0x31, 0x30, 0x3a, 0x30, 0x9, 0xc, 0x2, 0x6f, 0x6b, 0xa1, 0x3, 0x1, 0x1, 0xff, 0x30, 0x9, 0xc, 0x2, 0x6f, 0x61, 0xa1, 0x3, 0x1, 0x1, 0xff, 0x30, 0xb, 0xc, 0x4, 0x6f, 0x64, 0x65, 0x6c, 0xa1, 0x3, 0x1, 0x1, 0xff, 0x30, 0x15, 0xc, 0x4, 0x6f, 0x73, 0x67, 0x6e, 0xa0, 0x6, 0xc, 0x4, 0x72, 0x73, 0x65, 0x63, 0x30, 0x5, 0xa6, 0x3, 0x2, 0x1, 0x1}

// Environment identifies the App Attest environment an attestation was
// issued in.
type Environment int

// attestation environment
const (
	None        Environment = iota // zero value; never returned by a successful Verify
	Development                    // aaguid "appattestdevelop" or "appattestsandbox"
	Production                     // aaguid "appattest" + 7 zero bytes
)

// Sandbox is an alias of Development.
//
// Deprecated: use Development.
const Sandbox = Development

type Platform int

// platform
const (
	iOS Platform = iota
	macOS
)

func (e Environment) String() string {
	switch e {
	case Development:
		return "Development"
	case Production:
		return "Production"
	}
	return "Invalid Environment"
}

// cborAttestKey is a bit flag for a required CBOR map key of AttestationObject.
type cborAttestKey byte

const (
	cborAttestAuthData cborAttestKey = 1 << iota
	cborAttestFmt
	cborAttestStmt

	cborAttestAll = cborAttestAuthData | cborAttestFmt | cborAttestStmt
)

func (k cborAttestKey) Names() string {
	var names []string
	if k&cborAttestAuthData != 0 {
		names = append(names, "authData")
	}
	if k&cborAttestFmt != 0 {
		names = append(names, "fmt")
	}
	if k&cborAttestStmt != 0 {
		names = append(names, "attStmt")
	}
	return strings.Join(names, ", ")
}

// cborAttStmtKey is a bit flag for a required CBOR map key of AttStmt.
type cborAttStmtKey byte

const (
	cborAttStmtReceipt cborAttStmtKey = 1 << iota
	cborAttStmtX5c

	cborAttStmtAll = cborAttStmtReceipt | cborAttStmtX5c
)

func (k cborAttStmtKey) Names() string {
	var names []string
	if k&cborAttStmtReceipt != 0 {
		names = append(names, "receipt")
	}
	if k&cborAttStmtX5c != 0 {
		names = append(names, "x5c")
	}
	return strings.Join(names, ", ")
}

// AttestationObject represents the CBOR-encoded attestation object returned by the authenticator.
// In App Attest, it includes the authenticator data, format identifier, and Apple's attestation statement.
type AttestationObject struct {
	// The byteform version of the authenticator data, used in part for signature validation
	AuthData []byte `cbor:"authData"`
	// The format of the Attestation data.
	Format string `cbor:"fmt"`
	// Attestation statement containing certificate chain and receipt
	AttStmt AttStmt `cbor:"attStmt"`
}

// AttStmt represents the attestation statement in a WebAuthn AttestationObject.
// For App Attest, it includes the certificate chain (x5c) and the Apple-issued receipt.
type AttStmt struct {
	X5C     [][]byte `cbor:"x5c"`     // Certificate chain used for attestation
	Receipt []byte   `cbor:"receipt"` // Apple App Attest receipt
}

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

type Result struct {
	Environment             Environment
	Receipt                 []byte
	PublicKey               *ecdsa.PublicKey
	AppleBundleVersion      string
	AppleValidationCategory ValidationCategory
}

type AttestationService struct {
	// RootCertPool holds the loaded root CA certificates for signature verification.
	RootCertPool *x509.CertPool

	// App Identifier (format: teamID + "." + bundleID)
	AppID string
}

func NewAttestationService(pool *x509.CertPool, appID string) *AttestationService {
	return &AttestationService{RootCertPool: pool, AppID: appID}
}

// VerifyForiOS validates a single iOS attestation object and returns the result.
//
// appID is the App Identifier (format: teamID + "." + bundleID).
func (service *AttestationService) VerifyForiOS(attestObj *AttestationObject, appID string, clientDataHash, keyID []byte) (*Result, error) {
	return service.verify(iOS, attestObj, appID, clientDataHash, keyID)
}

// Verify validates a single attestation object and returns the result.
//
// Deprecated: use VerifyForiOS, which takes the App ID explicitly.
func (service *AttestationService) Verify(attestObj *AttestationObject, clientDataHash, keyID []byte) (*Result, error) {
	return service.verify(iOS, attestObj, service.AppID, clientDataHash, keyID)
}

func (service *AttestationService) verify(platform Platform, attestObj *AttestationObject, identifier string, clientDataHash, keyID []byte) (*Result, error) {
	if service.RootCertPool == nil {
		return nil, errors.New("root certificate pool is nil")
	}
	if attestObj == nil {
		return nil, errors.New("attestObj is nil")
	}
	if attestObj.Format != "apple-appattest" {
		return nil, fmt.Errorf("invalid attestation format: %q", attestObj.Format)
	}
	if len(attestObj.AuthData) == 0 {
		return nil, errors.New("authData: empty data")
	}
	if len(attestObj.AttStmt.X5C) == 0 {
		return nil, errors.New("AttStmt: empty data")
	}
	receipt := attestObj.AttStmt.Receipt
	intermediates := x509.NewCertPool()

	x5chain := attestObj.AttStmt.X5C
	if len(x5chain) < 2 {
		return nil, errors.New("x5c chain must contain credential and intermediate certificates")
	}
	credCert, err := x509.ParseCertificate(x5chain[0])
	if err != nil {
		return nil, fmt.Errorf("parsing certificate from ASN.1 data failed: %w", err)
	}
	for i, certDER := range x5chain[1:] {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("parsing intermediate certificate at index %d failed: %w", i+1, err)
		}
		intermediates.AddCert(cert)
	}

	// 1. Verify that the x5c array contains the intermediate and leaf certificates for App Attest,
	//  starting from the credential certificate in the first data buffer in the array (credcert).
	//  Verify the validity of the certificates using Apple’s App Attest root certificate.
	err = verifyCredentialCertificate(credCert, service.RootCertPool, intermediates)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}

	// 2. Create clientDataHash as the SHA256 hash of the one-time challenge sent to your app before performing the attestation,
	//  and append that hash to the end of the authenticator data (authData from the decoded object).
	// 3. Generate a new SHA256 hash of the composite item to create nonce.
	hash := sha256.New()
	hash.Write(attestObj.AuthData)
	hash.Write(clientDataHash)
	nonce := hash.Sum(nil)

	// 4. Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2, which is a DER-encoded ASN.1 sequence.
	//  Decode the sequence and extract the single octet string that it contains. Verify that the string equals nonce.
	credCertOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
	var credCertExtension []byte
	aclBlobOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 6}
	var aclBlobExtension []byte
	for _, ext := range credCert.Extensions {
		if ext.Id.Equal(credCertOID) {
			credCertExtension = ext.Value
		}
		if ext.Id.Equal(aclBlobOID) {
			aclBlobExtension = ext.Value
		}
	}
	if len(credCertExtension) == 0 {
		return nil, fmt.Errorf("certificate didn't contain credCert extension")
	}
	var sequence []asn1.RawValue
	if _, err = asn1.Unmarshal(credCertExtension, &sequence); err != nil {
		return nil, fmt.Errorf("credCert extension parse error: %w", err)
	}
	if len(sequence) != 1 {
		return nil, fmt.Errorf("invalid credCert extension structure")
	}
	var octetString asn1.RawValue
	if _, err = asn1.Unmarshal(sequence[0].Bytes, &octetString); err != nil {
		return nil, fmt.Errorf("credCert extension value parse error: %w", err)
	}
	if octetString.Class != asn1.ClassUniversal || octetString.Tag != asn1.TagOctetString {
		return nil, fmt.Errorf("invalid credCert extension value")
	}
	if !bytes.Equal(nonce, octetString.Bytes) {
		return nil, fmt.Errorf("credCert extension does not match nonce")
	}

	// for macOS
	if platform == macOS {
		// aclBlob Extension
		if len(aclBlobExtension) == 0 {
			return nil, fmt.Errorf("certificate didn't contain aclBlob extension")
		}
		var sequence []asn1.RawValue
		var octetString asn1.RawValue
		if _, err = asn1.Unmarshal(aclBlobExtension, &sequence); err != nil {
			return nil, fmt.Errorf("aclBlob extension parse error: %w", err)
		}
		if len(sequence) != 1 {
			return nil, fmt.Errorf("invalid aclBlob extension structure")
		}
		if _, err = asn1.Unmarshal(sequence[0].Bytes, &octetString); err != nil {
			return nil, fmt.Errorf("aclBlob extension value parse error: %w", err)
		}
		if octetString.Class != asn1.ClassUniversal || octetString.Tag != asn1.TagOctetString {
			return nil, fmt.Errorf("invalid aclBlob extension value")
		}
		if !bytes.Equal(expectedACL, octetString.Bytes) {
			return nil, fmt.Errorf("aclBlob does not match expected value")
		}
	}

	// 5. Create the SHA256 hash of the public key in credCert, and verify that it matches the key identifier from your app.
	pubkey, ok := credCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key algorithm")
	}
	pubkeyBytes, err := pubkey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("invalid ecdsa public key: %w", err)
	}
	pubkeyHash := sha256.Sum256(pubkeyBytes)
	if !bytes.Equal(pubkeyHash[:], keyID) {
		return nil, fmt.Errorf("the keyid is not match public key's hash")
	}

	// prepare AuthenticatorData
	authData := AuthenticatorData{}
	if err = authData.Unmarshal(attestObj.AuthData, true); err != nil {
		return nil, fmt.Errorf("authenticator data decoding failed: %w", err)
	}

	// 6. Compute the SHA256 hash of your app’s App ID, and verify that this is the same as the authenticator data’s RP ID hash.
	appIdHash := sha256.Sum256([]byte(identifier))
	if !bytes.Equal(authData.RPIDHash[:], appIdHash[:]) {
		return nil, ErrUnmatchRPIDHash
	}

	// 7. Verify that the authenticator data’s counter field equals 0.
	if authData.Counter != 0 {
		return nil, fmt.Errorf("authenticator data counter was not 0, received: %d", authData.Counter)
	}

	// 8. Verify that the authenticator data’s aaguid field is either appattestdevelop if operating in the development environment,
	//  or appattest followed by seven 0x00 bytes if operating in the production environment.
	aaguid := string(authData.CredentialData.AAGUID)
	var env Environment
	switch aaguid {
	case "appattest\x00\x00\x00\x00\x00\x00\x00":
		env = Production
	case "appattestdevelop", "appattestsandbox":
		env = Development
	default:
		return nil, fmt.Errorf("invalid aaguid value")
	}

	// 9. Verify that the authenticator data’s credentialId field is the same as the key identifier.
	if !bytes.Equal(authData.CredentialData.CredentialID, keyID) {
		return nil, fmt.Errorf("credential ID did not equal the provided key identifier")
	}

	return &Result{
		// Receipt from AttStmt.UnmarshalCBOR aliases the caller's input
		// buffer (ReadByteString in this cbor package is zero-copy despite
		// its name — there is no copying variant). Result.Receipt is meant
		// for long-term storage by callers, so it must be cloned here.
		Receipt:                 bytes.Clone(receipt),
		PublicKey:               pubkey,
		Environment:             env,
		AppleBundleVersion:      authData.AppleBundleVersion,
		AppleValidationCategory: ValidationCategory(authData.AppleValidationCategory),
	}, nil
}

// verifyCredentialCertificate verifies an App Attest credential chain without applying
// crypto/x509's default TLS ServerAuth extended-key-usage policy. App Attest credential
// certificates are attestation credentials, not TLS server certificates.
func verifyCredentialCertificate(credential *x509.Certificate, roots, intermediates *x509.CertPool) error {
	_, err := credential.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// UnmarshalCBOR decodes CBOR data into the AttestationObject.
//
// Used during registration to parse the authenticator’s attestation response.
func (ao *AttestationObject) UnmarshalCBOR(data []byte) error {
	var gotKeys cborAttestKey

	dec := cbor.NewDecoder(data)
	mt, ai, err := dec.ReadHeader()
	if err != nil {
		return fmt.Errorf("failed to read CBOR map header: %w", err)
	}
	if mt != cbor.Map {
		return fmt.Errorf("expected CBOR type Map (major type 5) for AttestationObject, got major type %d", mt)
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
		case "fmt":
			if gotKeys&cborAttestFmt != 0 {
				return fmt.Errorf("%w: %s", ErrDuplicateKey, key)
			}
			gotKeys |= cborAttestFmt
			mt, ai, err = dec.ReadHeader()
			if err != nil {
				return fmt.Errorf(`failed to read map value header (key "fmt") at index %d: %w`, i, err)
			}
			if mt != cbor.TextString {
				return fmt.Errorf(`expected string for format (key "fmt"), got major type %d`, mt)
			}
			val, err := dec.ReadTextString(ai)
			if err != nil {
				return fmt.Errorf(`failed to read format string (key "fmt"): %w`, err)
			}
			ao.Format = val
		case "authData":
			if gotKeys&cborAttestAuthData != 0 {
				return fmt.Errorf("%w: %s", ErrDuplicateKey, key)
			}
			gotKeys |= cborAttestAuthData
			mt, ai, err = dec.ReadHeader()
			if err != nil {
				return fmt.Errorf(`failed to read map value header (key "authData") at index %d: %w`, i, err)
			}
			if mt != cbor.ByteString {
				return fmt.Errorf(`expected bytestring for authData (key "authData"), got major type %d`, mt)
			}
			val, err := dec.ReadByteString(ai)
			if err != nil {
				return fmt.Errorf(`failed to read authData bytes (key "authData"): %w`, err)
			}
			ao.AuthData = val
		case "attStmt":
			if gotKeys&cborAttestStmt != 0 {
				return fmt.Errorf("%w: %s", ErrDuplicateKey, key)
			}
			gotKeys |= cborAttestStmt
			stmt := AttStmt{}
			if err = stmt.UnmarshalCBOR(dec); err != nil {
				return fmt.Errorf(`failed to unmarshal attStmt (key "attStmt"): %w`, err)
			}
			ao.AttStmt = stmt
		default:
			return fmt.Errorf("%w: %s", ErrUnknownKey, key)
		}
	}
	if missing := cborAttestAll &^ gotKeys; missing != 0 {
		return fmt.Errorf("%w: %s", ErrMissingKey, missing.Names())
	}

	return nil
}

// UnmarshalCBOR decodes the CBOR fields of the attestation statement (X5C and receipt).
func (as *AttStmt) UnmarshalCBOR(dec *cbor.Decoder) error {
	var gotKeys cborAttStmtKey

	mt, ai, err := dec.ReadHeader()
	if err != nil {
		return fmt.Errorf("failed to read attStmt map header: %w", err)
	}
	if mt != cbor.Map {
		return fmt.Errorf("expected CBOR type Map (major type 5) for attStmt, got major type %d", mt)
	}

	size, err := dec.ReadAdditional(ai)
	if err != nil {
		return fmt.Errorf("failed to read attStmt map size: %w", err)
	}
	for i := range size {
		mt, ai, err = dec.ReadHeader()
		if err != nil {
			return fmt.Errorf("failed to read attStmt map key header at index %d: %w", i, err)
		}
		if mt != cbor.TextString {
			return fmt.Errorf("expected string map key at index %d, got major type %d", i, mt)
		}
		key, err := dec.ReadUnsafeTextString(ai)
		if err != nil {
			return fmt.Errorf("failed to read attStmt map key string at index %d: %w", i, err)
		}
		switch key {
		case "receipt":
			if gotKeys&cborAttStmtReceipt != 0 {
				return fmt.Errorf("%w: %s", ErrDuplicateKey, key)
			}
			gotKeys |= cborAttStmtReceipt
			mt, ai, err = dec.ReadHeader()
			if err != nil {
				return fmt.Errorf(`failed to read map value header (key "receipt") at index %d: %w`, i, err)
			}
			if mt != cbor.ByteString {
				return fmt.Errorf(`expected bytestring for receipt (key "receipt"), got major type %d`, mt)
			}
			val, err := dec.ReadByteString(ai)
			if err != nil {
				return fmt.Errorf(`failed to read receipt bytes (key "receipt"): %w`, err)
			}
			as.Receipt = val
		case "x5c":
			if gotKeys&cborAttStmtX5c != 0 {
				return fmt.Errorf("%w: %s", ErrDuplicateKey, key)
			}
			gotKeys |= cborAttStmtX5c
			mt, ai, err = dec.ReadHeader()
			if err != nil {
				return fmt.Errorf(`failed to read map value header (key "x5c") at index %d: %w`, i, err)
			}
			if mt != cbor.Array {
				return fmt.Errorf(`expected array for x5c (key "x5c"), got major type %d`, mt)
			}
			count, err := dec.ReadAdditional(ai)
			if err != nil {
				return fmt.Errorf(`failed to read x5c array size (key "x5c"): %w`, err)
			}
			if count > maxX5CCerts {
				return fmt.Errorf(`x5c array too large (key "x5c"): got %d, max %d`, count, maxX5CCerts)
			}
			array := make([][]byte, count)
			for j := range count {
				mt, ai, err = dec.ReadHeader()
				if err != nil {
					return fmt.Errorf("failed to read x5c array item header at index %d: %w", j, err)
				}
				if mt != cbor.ByteString {
					return fmt.Errorf("expected bytestring in x5c array at index %d, got major type %d", j, mt)
				}
				val, err := dec.ReadByteString(ai)
				if err != nil {
					return fmt.Errorf("failed to read x5c array item bytes at index %d: %w", j, err)
				}
				array[j] = val
			}
			as.X5C = array
		default:
			return fmt.Errorf("%w: %s", ErrUnknownKey, key)
		}
	}
	if missing := cborAttStmtAll &^ gotKeys; missing != 0 {
		return fmt.Errorf("%w: %s", ErrMissingKey, missing.Names())
	}

	return nil
}
