package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"io/ioutil"

	cbor "github.com/brianolson/cbor_go"
	"github.com/pkg/errors"
)

type Environment int

// attestation envirom
const (
	None                    = 0
	Development Environment = 1 // the App Attest sandbox environment.
	Production  Environment = 2 // The App Attest production environment.
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
		return nil, errors.Errorf("invalid receipt value")
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	fileBytes, err := ioutil.ReadFile(service.PathForRootCA)
	if err != nil {
		return nil, errors.Wrapf(err, "pem file read failed")
	}
	if ok := roots.AppendCertsFromPEM(fileBytes); !ok {
		return nil, errors.Errorf("adding root cerfificate to pool")
	}

	x5cArray, ok := attestObj.AttStatement["x5c"].([]interface{})
	if !ok {
		return nil, errors.Errorf("invalid x5c value")
	}

	for _, x5c := range x5cArray {
		raw, ok := x5c.([]byte)
		if !ok {
			return nil, errors.Errorf("invalid certificate from x5c cert chain 1")
		}
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, errors.Wrapf(err, "parsing certificate from ASN.1 data failed")
		}
		if cert.IsCA {
			intermediates.AddCert(cert)
		}
	}

	rawBytes, ok := x5cArray[0].([]byte)
	if !ok {
		return nil, errors.Errorf("invalid certificate from x5c cert chain 2")
	}
	credCert, err := x509.ParseCertificate(rawBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "parsing certificate from ASN.1 data failed")
	}

	// 1. Verify that the x5c array contains the intermediate and leaf certificates for App Attest,
	//  starting from the credential certificate in the first data buffer in the array (credcert).
	//  Verify the validity of the certificates using Apple’s App Attest root certificate.
	_, err = credCert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates})
	if err != nil {
		return nil, errors.Wrap(err, "invalid certificate")
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
		return nil, errors.Errorf("certificate didn't contain credCert extension")
	}
	var certOctet []asn1.RawValue
	if _, err = asn1.Unmarshal(credCertId, &certOctet); err != nil {
		return nil, errors.Wrap(err, "credCertId parse error")
	}
	var cert asn1.RawValue
	if _, err = asn1.Unmarshal(certOctet[0].Bytes, &cert); err != nil {
		return nil, errors.Wrap(err, "certOctet parse error")
	}
	if !bytes.Equal(nonce[:], cert.Bytes) {
		return nil, errors.Errorf("credCert extension does not match nonce")
	}

	// 5. Create the SHA256 hash of the public key in credCert, and verify that it matches the key identifier from your app.
	pubkey, ok := credCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.Errorf("invalid key algorithm")
	}
	pubkeyHash := sha256.Sum256(elliptic.Marshal(pubkey.Curve, pubkey.X, pubkey.Y))
	if !bytes.Equal(pubkeyHash[:], keyID) {
		return nil, errors.Errorf("the keyid is not match public key's hash")
	}

	// prepare AuthenticatorData
	authData := AuthenticatorData{}
	if err = authData.Unmarshal(attestObj.AuthData); err != nil {
		return nil, errors.Errorf("authenticator data decoding failed")
	}
	if !authData.HasAttestedCredentialData() {
		return nil, errors.Errorf("attestation missing attested credential data flag")
	}

	// 6. Compute the SHA256 hash of your app’s App ID, and verify that this is the same as the authenticator data’s RP ID hash.
	appIdHash := sha256.Sum256([]byte(service.AppID))
	if !bytes.Equal(authData.RPIDHash[:], appIdHash[:]) {
		return nil, ErrUnmatchRPIDHash
	}

	// 7. Verify that the authenticator data’s counter field equals 0.
	if authData.Counter != 0 {
		return nil, errors.Errorf("authenticator data counter was not 0, received: %d", authData.Counter)
	}

	// 8. Verify that the authenticator data’s aaguid field is either appattestdevelop if operating in the development environment,
	//  or appattest followed by seven 0x00 bytes if operating in the production environment.
	aaguid := string(bytes.Trim(authData.CredentialData.AAGUID, "\x00"))
	var env Environment
	switch aaguid {
	case "appattest":
		env = Production
	case "appattestdevelop":
		env = Development
	default:
		return nil, errors.Errorf("invalid aaguid value")
	}

	// 9. Verify that the authenticator data’s credentialId field is the same as the key identifier.
	if !bytes.Equal(authData.CredentialData.CredentialID, keyID) {
		return nil, errors.Errorf("Credential ID did not equal the provided key identifier")
	}

	return &Result{Receipt: receipt, PublicKey: pubkey, Environment: env}, nil
}
