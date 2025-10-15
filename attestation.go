package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"os"

	cbor "github.com/brianolson/cbor_go"
)

type Environment int

// attestation envirom
const (
	None                   = 0
	Sandbox    Environment = 1 // the App Attest sandbox environment.
	Production Environment = 2 // The App Attest production environment.
)

func (e Environment) String() string {
	switch e {
	case Sandbox:
		return "Sandbox"
	case Production:
		return "Production"
	}
	return "Invalid Environment"
}

type AttestationObject struct {
	// The byteform version of the authenticator data, used in part for signature validation
	AuthData []byte `cbor:"authData"`
	// The format of the Attestation data.
	Format string `cbor:"fmt"`
	// The attestation statement data sent back if attestation is requested.
	AttStatement map[string]interface{} `cbor:"attStmt,omitempty"`
}

func (obj *AttestationObject) Unmarshal(rawBytes []byte) error {
	dec := cbor.NewDecoder(bytes.NewReader(rawBytes))
	return dec.Decode(obj)
}

type Result struct {
	Environment Environment
	Receipt     []byte
	PublicKey   *ecdsa.PublicKey
}

type AttestationService struct {
	// Apple’s App Attest root certificate file path
	PathForRootCA string
	// App Identifier (format: teamID + "." + bundleID)
	AppID string
}

// Verify validate a single attestation object and return result object.
func (service *AttestationService) Verify(attestObj *AttestationObject, clientDataHash, keyID []byte) (*Result, error) {
	receipt, ok := attestObj.AttStatement["receipt"].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid receipt value")
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	fileBytes, err := os.ReadFile(service.PathForRootCA)
	if err != nil {
		return nil, fmt.Errorf("pem file read failed: %w", err)
	}
	if ok := roots.AppendCertsFromPEM(fileBytes); !ok {
		return nil, fmt.Errorf("adding root cerfificate to pool")
	}

	x5cArray, ok := attestObj.AttStatement["x5c"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid x5c value")
	}

	for _, x5c := range x5cArray {
		raw, ok := x5c.([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid certificate from x5c cert chain 1")
		}
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate from ASN.1 data failed: %w", err)
		}
		if cert.IsCA {
			intermediates.AddCert(cert)
		}
	}

	rawBytes, ok := x5cArray[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid certificate from x5c cert chain 2")
	}
	credCert, err := x509.ParseCertificate(rawBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate from ASN.1 data failed: %w", err)
	}

	// 1. Verify that the x5c array contains the intermediate and leaf certificates for App Attest,
	//  starting from the credential certificate in the first data buffer in the array (credcert).
	//  Verify the validity of the certificates using Apple’s App Attest root certificate.
	_, err = credCert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates})
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}

	// 2. Create clientDataHash as the SHA256 hash of the one-time challenge sent to your app before performing the attestation,
	//  and append that hash to the end of the authenticator data (authData from the decoded object).
	// 3. Generate a new SHA256 hash of the composite item to create nonce.
	nonce := sha256.Sum256(append(attestObj.AuthData, clientDataHash...))

	// 4. Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2, which is a DER-encoded ASN.1 sequence.
	//  Decode the sequence and extract the single octet string that it contains. Verify that the string equals nonce.
	credCertOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
	var credCertId []byte
	for _, ext := range credCert.Extensions {
		if ext.Id.Equal(credCertOID) {
			credCertId = ext.Value
		}
	}
	if len(credCertId) <= 0 {
		return nil, fmt.Errorf("certificate didn't contain credCert extension")
	}
	var certOctet []asn1.RawValue
	if _, err = asn1.Unmarshal(credCertId, &certOctet); err != nil {
		return nil, fmt.Errorf("credCertId parse error: %w", err)
	}
	var cert asn1.RawValue
	if _, err = asn1.Unmarshal(certOctet[0].Bytes, &cert); err != nil {
		return nil, fmt.Errorf("certOctet parse error: %w", err)
	}
	if !bytes.Equal(nonce[:], cert.Bytes) {
		return nil, fmt.Errorf("credCert extension does not match nonce")
	}

	// 5. Create the SHA256 hash of the public key in credCert, and verify that it matches the key identifier from your app.
	pubkey, ok := credCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key algorithm")
	}
	pubkeyHash := sha256.Sum256(MarshalUncompressed(pubkey))
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
	aaguid := string(bytes.Trim(authData.CredentialData.AAGUID, "\x00"))
	var env Environment
	switch aaguid {
	case "appattest":
		env = Production
	case "appattestdevelop":
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

// MarshalUncompressed encodes an ECDSA public key into the uncompressed form.
//
// This function produces the same output as the deprecated elliptic.Marshal()
// function, without triggering deprecation warnings in Go 1.21+.
//
// The returned byte slice has the following structure:
//
//	0x04 || X || Y
//
// where:
//   - 0x04 indicates the "uncompressed" point format as defined in SEC 1,
//   - X and Y are the big-endian, zero-padded coordinates of the public key,
//     each with a length equal to (curve.BitSize + 7) / 8.
//
// This representation is commonly used in cryptographic protocols such as
// Apple's App Attest service and WebAuthn when computing a SHA-256 hash
// over a raw ECDSA public key.
func MarshalUncompressed(pub *ecdsa.PublicKey) []byte {
	byteLen := (pub.Curve.Params().BitSize + 7) >> 3
	x := pub.X.FillBytes(make([]byte, byteLen))
	y := pub.Y.FillBytes(make([]byte, byteLen))
	data := make([]byte, 1+2*byteLen)
	data[0] = 0x04 // Uncompressed point indicator
	copy(data[1:1+byteLen], x)
	copy(data[1+byteLen:], y)
	return data
}
