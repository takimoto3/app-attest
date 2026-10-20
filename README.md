# App-Attest
[![](https://img.shields.io/badge/go-%3E%3D%201.26-blue)](#Installation)
[![Go Reference](https://pkg.go.dev/badge/github.com/takimoto3/app-attest.svg)](https://pkg.go.dev/github.com/takimoto3/app-attest)

App-Attest is a Go package that implements the server-side validation of both attestations and assertions that can be obtained using the [DCAppAttestService](https://developer.apple.com/documentation/devicecheck/dcappattestservice).

## Features
* Validate attestations
* Validate assertions (including the iOS 27+ bundle version / validation category extensions)
* Assess fraud risk by requesting and analyzing risk data from Apple's servers

## System Requirements

* Go 1.26 (or newer)

## Installation

```sh
go get github.com/takimoto3/app-attest
```

## Prerequisites

Apple's root certificates are required for validation. Download them as described in the Apple documentation below.

- **Attestation validation:** `Apple_App_Attestation_Root_CA.pem`
  ("App Attest root certificate" in [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server))
- **Receipt validation:** `AppleRootCA-G3.cer`
  ("Apple public root certificate" in [Assessing fraud risk](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk))

## Usage

### Attestation
Generate a key pair and attestation in your app as specified in the [documentation](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity).

For server-side validation, provide the path to the App Attest root certificate (see [Prerequisites](#prerequisites)) when initializing the AttestationService.

Validate the attestation by calling:
```go
import (
    "crypto/sha256"

    attest "github.com/takimoto3/app-attest"
    "github.com/takimoto3/app-attest/certs"
)

var keyID = []byte(.....) // DCAppAttestService.generateKey returned value and base64.StdEncoding.DecodeString
var challenge = []byte(.....) // one-time challenge from the server
var clientDataHash = sha256.Sum256(challenge)
var attestation = []byte(.....) // DCAppAttestService.attestKey returned value

attestationObj := &attest.AttestationObject{}
if err := attestationObj.UnmarshalCBOR(attestation); err != nil {
    // handle error...
}
pool, err := certs.LoadCertFiles("path/to/Apple_App_Attestation_Root_CA.pem")
if err != nil {
    // handle error...
}
service := &attest.AttestationService{RootCertPool: pool}

result, err := service.VerifyForiOS(
    attestationObj,
    "<TEAM ID>.<Bundle ID>", // Your App ID
    clientDataHash[:],
    keyID,
)
if err != nil {
    // handle error...
}

// use result ....
```

`VerifyForiOS` returns `attest.Result` if the validation succeeds. It contains:

* `PublicKey` and `Receipt` (both should be saved)
* `Environment`: `attest.Production` or `attest.Development`
* `AppleBundleVersion` and `AppleValidationCategory` (iOS 27+ only; empty / zero on earlier versions)

> **Note:** `AttestationService.Verify` (which takes the App ID from the service's `AppID` field) is deprecated. Use `VerifyForiOS`, which takes the App ID explicitly. `attest.Sandbox` is likewise a deprecated alias of `attest.Development`.

### Assertion

If the attestation is successful, your app will create and validate the assertion as specified in the [documentation](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity).

Verify the assertion by calling:
```go
var clientData = []byte(`{"levelId":"1234","action":"getGameLevel","challenge":"..."}`) // client request (JSON data case)
var clientChallenge = "..." // Extract the challenge from clientData
var assertion = []byte(....) // DCAppAttestService.generateAssertion returned value

assertionObj := &attest.AssertionObject{}
if err := assertionObj.UnmarshalCBOR(assertion); err != nil {
    // handle error...
}

// Load the state for this key from your own storage on every request.
// Do not derive AppID from the client's request.
state := attest.AssertionState{
    AppID:             "<TEAM ID>.<Bundle ID>", // recorded at attestation time
    PublicKey:         <stored_publickey>,      // *ecdsa.PublicKey saved from the attestation
    OriginalChallenge: <stored_challenge>,      // challenge the server issued for this assertion
    Counter:           <stored_counter>,        // last accepted sign count (0 if none yet)
}

service := &attest.AssertionService{} // can be shared across requests
result, err := service.VerifyWithState(assertionObj, clientChallenge, clientData, state)
if err != nil {
    // handle error...
}

// result.Counter: persist it (see below)
// result.AppleBundleVersion / result.AppleValidationCategory: iOS 27+ only
```

Notes:
* Pass the original `clientData` bytes received from the client to
  `VerifyWithState`. Do not re-encode the JSON before verification.
* `result.Counter` is the new sign count. Persist it with an atomic compare-and-set, and reject any future assertion whose counter is not strictly greater.
* Challenge generation, expiry and single use are the caller's responsibility; this package only compares it with the value passed to `VerifyWithState`.
* `state` is read-only. Error messages should not be returned to clients.
* `AssertionService.Verify` (which reads `AppID`, `Challenge`, `Counter` and `PublicKey` from the service's fields and returns only the counter) is deprecated. Use `VerifyWithState`.

### Assessing Fraud Risk

You can assess the risk of fraud by requesting a new receipt from Apple's servers, which contains a risk metric. This metric indicates the number of attested keys for your app on a particular device over the past 30 days.

The following example shows how to use `fraud.Client` to get a new receipt and `receipt.ReceiptVerifier` to parse and validate it.

```go
import (
    "context"
    "crypto/ecdsa"
    "errors"
    "fmt"
    "log"

    "github.com/takimoto3/app-attest/certs"
    "github.com/takimoto3/app-attest/fraud"
    "github.com/takimoto3/app-attest/fraud/receipt"
    "github.com/takimoto3/appleapi-core/token"
)

func main() {
    // The App ID and attested public key stored after the initial attestation.
    // Verify() checks that the public key in receipt field 3 matches
    // the attested public key stored from the initial attestation.
    var appID string
    var publicKey *ecdsa.PublicKey

    // The receipt from the initial attestation, which you should have stored.
    var initialReceipt []byte


    // --- 0. Authentication setup ---
    // You need a token.Provider for JWT authentication.
    // Load your private key from a .p8 file.
    privKey, err := token.LoadPKCS8File("<PATH_TO_YOUR_AUTHKEY.P8>") // e.g., "certs/AuthKey.p8"
    if err != nil {
        log.Fatalf("Failed to load private key: %v", err)
    }
    // Create a new token provider with your Key ID, Team ID, and private key.
    tokenProvider := token.NewProvider("<YOUR_KEY_ID>", "<YOUR_TEAM_ID>", privKey)

    // --- 1. Create clients ---
    // Create a fraud client. Options may be appleapi.Option values (e.g.
    // appleapi.WithDevelopment()) and/or fraud.Option values
    // (e.g. fraud.WithResponseBodyLimit(1 << 20)).
    fraudClient, err := fraud.NewClient(tokenProvider)
    if err != nil {
        log.Fatalf("Failed to create fraud client: %v", err)
    }
    // Create a receipt verifier with the Apple public root certificate (see "Prerequisites").
    rootCAPool, err := certs.LoadCertFiles("path/to/AppleRootCA-G3.cer")
    if err != nil {
        log.Fatalf("Failed to load root CA: %v", err)
    }
    receiptVerifier := receipt.NewReceiptVerifier(rootCAPool)
    // Optional: receiptVerifier.MaxAge = 5 * time.Minute (default)

    // --- 2. Request a new receipt from Apple ---
    // The fraud.Client handles the HTTP POST to Apple's server.
    newReceipt, err := fraudClient.Do(context.Background(), initialReceipt)
    if err != nil {
        // Handle specific cases like "not before date".
        if errors.Is(err, fraud.ErrNotBeforeDate) {
            log.Println("Requested before the receipt's not-before date. Risk metric not updated.")
            // This is not a fatal error. You can continue with the old receipt.
            return
        }
        // Handle other potential errors (e.g., network issues, invalid token).
        log.Fatalf("Failed to get new receipt from Apple: %v", err)
    }

    // --- 3. Verify the new receipt ---
    // Verify checks the PKCS#7 signature and certificate chain, then validates
    // the App ID, attested public key, receipt type, creation time (MaxAge),
    // and the presence of the risk metric (for RECEIPT type).
    verifiedReceipt, err := receiptVerifier.Verify(newReceipt.Receipt, appID, publicKey)
    if err != nil {
        log.Fatalf("Failed to verify new receipt: %v", err)
    }

    // --- 4. Use the risk metric ---
    fmt.Printf("Successfully verified new receipt.\n")
    fmt.Printf("Risk Metric: %d\n", verifiedReceipt.RiskMetric)
    fmt.Printf("Receipt Type: %s\n", verifiedReceipt.Type)
    fmt.Printf("Creation Time: %v\n", verifiedReceipt.CreationTime)
    fmt.Printf("Not Before: %v\n", verifiedReceipt.NotBefore)
    fmt.Printf("Expiration Time: %v\n", verifiedReceipt.ExpirationTime)

    // You should now store the new receipt (`newReceipt.Receipt`)
    // to use it for the next refresh.
}
```

> **Note:** `ReceiptVerifier.ParseAndVerify`, `Receipt.Validate` and `Receipt.Dump` are deprecated. Use `Verify`. `fraud.ErrNotModified` is a deprecated alias of `fraud.ErrNotBeforeDate`.

## Testing

Run standard tests using the standard Go toolchain:

```sh
go test ./...
```

Most tests are self-contained: they generate their own certificate chains and payloads at runtime, so no fixture files are needed.

### Golden tests (optional)

If you want to verify against real data produced by an actual device, you can provide golden fixture files. Each golden test is **skipped** when its file is absent.

To accurately test time-sensitive certificate and receipt validation logic against fixed golden data without expiration issues, run tests using the testtime library overlay:
```sh
go test -overlay=$(go run github.com/tenntenn/testtime/cmd/testtime@latest) ./...
```

| Test | Fixture file |
|---|---|
| `TestGolden_AttestationService_Verify` | `testdata/golden_attestation.json` |
| `TestGolden_AssertionService_Verify` | `testdata/golden_assertion.json` |
| `TestGolden_ReceiptVerifier_Verify` | `fraud/receipt/testdata/golden_receipt.json` |

These files are listed in `.gitignore` (`testdata/*.json`, `fraud/receipt/testdata/*.json`) because they contain environment-specific data. Don't commit them.

For the attestation and receipt golden tests, the clock is set with `testtime` (to `testDate` for attestation, and to just after each receipt's creation time for receipts), so the tests stay valid after the certificates or the 5-minute receipt window expire.

### Generating Custom Test Data

To create your own golden data, run `DCAppAttestService` on a physical iOS
device and export the results as Base64 strings, along with the required
metadata (`teamIdentifier`, `bundleIdentifier`, `publicKeyPEM`, etc.).

Attestation and assertion fixtures can be produced directly from the device:

- **Attestation:** the output of `attestKey`, the key ID, and the SHA-256
  hash of the challenge that was passed to `attestKey`.
- **Assertion:** the output of `generateAssertion` for the first request
  after attestation, the client data, and the challenge. Use the same key
  that produced `publicKeyPEM`.

**Receipt fixtures require an extra step.** The receipt embedded in an
attestation object has the type `ATTEST` and does not contain a risk metric.
To obtain a `RECEIPT`-type receipt (with `riskMetric`), you must send the
attestation's receipt to Apple's servers, which requires an App Attest
authentication key (`.p8`):


1. Verify the attestation and keep `result.Receipt` and `result.PublicKey`.
   `result.Receipt` can also be used as an `ATTEST`-type fixture as is.
2. Call `fraud.Client.Do` with that receipt to request a new one from Apple.
3. Save `newReceipt.Receipt` as `receiptBase64`, and fill in `properties`
   (`type`, `creationTime`, `notBefore`, `expirationTime`, `riskMetric`)
   from the values returned by `receiptVerifier.Verify`.
   `creationTime` is important: the golden test sets the clock to just after
   this time, so the receipt can be verified later without hitting the
   5-minute `MaxAge` limit.


Note that Apple only returns an updated receipt after the previous
receipt's not-before date, so you may need to wait between requests
(see `fraud.ErrNotBeforeDate`).

Save the fixtures to `testdata/golden_attestation.json`,
`testdata/golden_assertion.json`, and
`fraud/receipt/testdata/golden_receipt.json`, following the field tables below.

### Golden Fixture Format

Each fixture is a JSON file with the fields described below.

#### Attestation Fields (`golden_attestation.json`)

The file contains a single JSON object (not an array).

| JSON Field Name | Type (JSON) | Description |
|---|---|---|
| `attestationBase64` | `string` | Base64 encoded data of the Attestation object returned by `attestKey` |
| `clientDataHashSha256Base64` | `string` | Base64 encoded SHA-256 hash of the challenge, i.e. the `clientDataHash` passed to `attestKey` (not the raw challenge) |
| `keyIdBase64` | `string` | Base64 encoded Key ID returned by `generateKey` |
| `publicKeyPEM` | `string` | Public key (ECDSA, PKIX) in PEM format. Must match the key in the attestation |
| `environment` | `string` | `development` or `production` |
| `testDate` | `string` | **Required.** RFC 3339 timestamp at which the attestation certificates are still valid. The test sets the clock to this value |
| `teamIdentifier` | `string` | Team ID |
| `bundleIdentifier` | `string` | App's Bundle ID |

The test checks that the public key and environment match, and that the
result contains a receipt.

#### Assertion Fields (`golden_assertion.json`)

The file contains a single JSON object (not an array).

| JSON Field Name | Type (JSON) | Description |
|---|---|---|
| `assertionBase64` | `string` | Base64 encoded data of the Assertion object returned by `generateAssertion` |
| `clientDataBase64` | `string` | Base64 encoded client data, exactly as it was hashed and passed to `generateAssertion` |
| `challengeBase64` | `string` | Base64 encoded challenge used as `clientChallenge` in `VerifyWithState`. The decoded bytes are used as-is as the challenge string |
| `publicKeyPEM` | `string` | Attested public key (ECDSA, PKIX) in PEM format |
| `teamIdentifier` | `string` | Team ID |
| `bundleIdentifier` | `string` | App's Bundle ID |

The test assumes that no assertion has been accepted for this key yet
(stored counter `0`) and expects the new counter to be `1`. Use the
**first** assertion generated after the attestation, and do not re-encode
`clientData`.

#### Receipt Fields (`golden_receipt.json`)

The file has a top-level `receipt` array. Add one element per receipt
you want to verify; both `ATTEST` and `RECEIPT` types are supported.
Each element has:

| JSON Field Name | Type (JSON) | Description |
|---|---|---|
| `type` | `string` | Used as the subtest name only |
| `teamIdentifier` / `bundleIdentifier` | `string` | Team ID and Bundle ID |
| `publicKeyPEM` | `string` | Attested public key in PEM format |
| `receiptBase64` | `string` | Base64 encoded PKCS#7 receipt |
| `properties` | `object` | Expected values (see below) |

The `properties` object has the following fields:

| JSON Field Name | Type (JSON) | Description |
|---|---|---|
| `type` | `string` | Expected receipt type: `ATTEST` or `RECEIPT` |
| `creationTime` | `string` | RFC 3339. **Required**: the test sets the clock to one minute after this time |
| `notBefore` | `string` | RFC 3339 |
| `expirationTime` | `string` | RFC 3339 |
| `riskMetric` | `number` | Expected risk metric. Omit for `ATTEST` (treated as `0`) |

The receipt golden test also requires `fraud/receipt/testdata/AppleRootCA-G3.cer`, and the attestation golden test requires `testdata/Apple_App_Attestation_Root_CA.pem` (see [Prerequisites](#prerequisites)).

## References

*   [DeviceCheck](https://developer.apple.com/documentation/devicecheck)
*   [Establishing your app's integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
*   [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
*   [Attestation Object Validation Guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide)
*   [Preparing to use the app attest service](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service)
*   [Assessing fraud risk](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk)

## Acknowledgements

I referred to [appattest](https://github.com/bas-d/appattest) by Bas Doorn when creating this library. Their work was a valuable reference.


## License
App-Attest is available under the MIT license. See the LICENSE file for more info.
