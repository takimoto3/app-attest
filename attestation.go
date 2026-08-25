package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/takimoto3/app-attest/cbor"
)

type Environment int

// attestation envirom
const (
	None       Environment = iota
	Sandbox                // the App Attest sandbox environment.
	Production             // The App Attest production environment.
)

type Platform int

// platform
const (
	iOS Platform = iota
	macOS
)

var expectedACLBlob = func() []byte {
	val, err := base64.StdEncoding.DecodeString("MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB")
	if err != nil {
		panic(err)
	}
	return val
}()

func (e Environment) String() string {
	switch e {
	case Sandbox:
		return "Sandbox"
	case Production:
		return "Production"
	}
	return "Invalid Environment"
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

type Result struct {
	Environment Environment
	Receipt     []byte
	PublicKey   *ecdsa.PublicKey
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

// Verify validate a single attestation object and return result object.
func (service *AttestationService) Verify(attestObj *AttestationObject, clientDataHash, keyID []byte) (*Result, error) {
	return service.verify(iOS, attestObj, clientDataHash, keyID)
}

func (service *AttestationService) verify(platform Platform, attestObj *AttestationObject, clientDataHash, keyID []byte) (*Result, error) {
	if attestObj.Format != "apple-appattest" {
		return nil, fmt.Errorf("invalid attestation format: %q", attestObj.Format)
	}
	receipt := attestObj.AttStmt.Receipt
	if len(receipt) == 0 {
		return nil, fmt.Errorf("invalid attestation: missing receipt")
	}
	roots := service.RootCertPool.Clone()
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
	err = verifyCredentialCertificate(credCert, roots, intermediates)
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
		if !bytes.Equal(expectedACLBlob, octetString.Bytes) {
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
	if err = authData.Unmarshal(attestObj.AuthData); err != nil {
		return nil, fmt.Errorf("authenticator data decoding failed")
	}
	if !authData.HasAttestedCredentialData() {
		return nil, fmt.Errorf("attestation missing attested credential data flag")
	}

	// 6. Compute the SHA256 hash of your app’s App ID, and verify that this is the same as the authenticator data’s RP ID hash.
	appIdHash := sha256.Sum256([]byte(service.AppID))
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
		env = Sandbox
	default:
		return nil, fmt.Errorf("invalid aaguid value")
	}

	// 9. Verify that the authenticator data’s credentialId field is the same as the key identifier.
	if !bytes.Equal(authData.CredentialData.CredentialID, keyID) {
		return nil, fmt.Errorf("credential ID did not equal the provided key identifier")
	}

	return &Result{Receipt: receipt, PublicKey: pubkey, Environment: env}, nil
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
	dec := cbor.NewDecoder(data)
	mt, ai, err := dec.ReadHeader()
	if err != nil {
		return err
	}
	if mt != cbor.Map {
		return fmt.Errorf("cbor: expected map for AttestationObject got %v", mt)
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
		key, err := dec.ReadUnsafeTextString(ai)
		if err != nil {
			return err
		}
		switch key {
		case "fmt":
			mt, ai, err = dec.ReadHeader()
			if err != nil {
				return err
			}
			if mt != cbor.TextString {
				return fmt.Errorf("cbor: expected textstring for \"fmt\", got %v", mt)
			}
			val, err := dec.ReadTextString(ai)
			if err != nil {
				return err
			}
			ao.Format = val
		case "authData":
			mt, ai, err = dec.ReadHeader()
			if err != nil {
				return err
			}
			if mt != cbor.ByteString {
				return fmt.Errorf("cbor: expected bytestring for \"authData\", got %v", mt)
			}
			val, err := dec.ReadByteString(ai)
			if err != nil {
				return err
			}
			ao.AuthData = val
		case "attStmt":
			stmt := AttStmt{}
			if err = stmt.UnmarshalCBOR(dec); err != nil {
				return err
			}
			ao.AttStmt = stmt
		}
	}
	return nil
}

// UnmarshalCBOR decodes the CBOR fields of the attestation statement (X5C and receipt).
func (as *AttStmt) UnmarshalCBOR(dec *cbor.Decoder) error {
	mt, ai, err := dec.ReadHeader()
	if err != nil {
		return err
	}
	if mt != cbor.Map {
		return fmt.Errorf("cbor: expected map for \"attStmt\", got %v", mt)
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
			return fmt.Errorf("cbor: expected textstring for attStmt map key got %v", mt)
		}
		key, err := dec.ReadUnsafeTextString(ai)
		if err != nil {
			return err
		}
		switch key {
		case "receipt":
			mt, ai, err = dec.ReadHeader()
			if err != nil {
				return err
			}
			if mt != cbor.ByteString {
				return fmt.Errorf("cbor: expected bytestring for \"receipt\", got %v", mt)
			}
			val, err := dec.ReadByteString(ai)
			if err != nil {
				return err
			}
			as.Receipt = val
		case "x5c":
			mt, ai, err = dec.ReadHeader()
			if err != nil {
				return err
			}
			if mt != cbor.Array {
				return fmt.Errorf("cbor: expected array for \"x5c\", got %v", mt)
			}
			size, err := dec.ReadAdditional(ai)
			if err != nil {
				return err
			}
			array := make([][]byte, size)
			for i := 0; i < int(size); i++ {
				mt, ai, err = dec.ReadHeader()
				if err != nil {
					return err
				}
				if mt != cbor.ByteString {
					return fmt.Errorf("cbor: expected bytestring in \"x5c array\", got %v", mt)
				}
				val, err := dec.ReadByteString(ai)
				if err != nil {
					return err
				}
				array[i] = val
			}
			as.X5C = array
		}
	}
	return nil
}
