# App-Attest
[![](https://img.shields.io/badge/go-%3E%3D%201.23-blue)](#Installation)

App-Attest is a Go package that implements the server-side validation of both attestations and assertions that can be obtained using the [DCAppAttestService](https://developer.apple.com/documentation/devicecheck/dcappattestservice).
 * (NOT SUPPORT) Request and analyze risk data from server-to-server calls using recipes

## System Requirements

* Go 1.23 (or newer)

## Installation
```sh
go install github.com/takimoto3/app-attest
```


## Usage

### Attestation
Generate a key pair and attestation in your app as specified in the [documentation](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity).

Validate the attestation by calling:
```go
import "github.com/takimoto3/app-attest/certs"

var keyID = []byte(.....) // DCAppAttestService.generateKey returned value and base64.StdEncoding.DecodeString
var challenge = []byte(.....) // one-time challenge from the server
var clientDataHash = sha256.Sum256(challenge)
var attestation = []byte(.....) // DCAppAttestService.attestKey returned value

attestationObj := &attest.AttestationObject{}
err := attestationObj.Unmarshal(attestation)
if err != nil {
    // handle error...
}

pool, err := certs.LoadCertFiles("testdata/Apple_App_Attestation_Root_CA.pem") // Path to your root CA file
if err != nil {
    // handle error...
}
service := attest.NewAttestationService(
    pool, // cert pool
    "<TEAM ID>.<Bundle ID>",   // Your App ID
)

result, err := service.Verify(attestObject, clientDataHash[:], keyID)
if err != nil {
    // handle error...
}

// use result ....
```

The `Verify` function returns `attest.Result` (containing the public key, receipt, and environment) if the validation succeeds. The public key and receipt should be saved.

### Assertion

If the attestation is successful, your app will create and validate the assertion as specified in the [documentation](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity).

Verify the assertion by calling:
```go
var challenge = []byte(....) // one-time challenge from the server
var cliendData = []byte("{..., "challenge":"<challenge data>", .....}") // client request(JSON data case)
var assertion = []byte(....) // DCAppAttestService.generateAssertion returned value

assertionObj := &attest.AssertionObject{}
err := assertionObject.Unmarshal(assertion)
if err != nil {
    // handle error...
}

service := attest.AssertionService{
    AppID:     "<TEAM ID>.<Bundle ID>",
    Challenge: <stored_challenge>,
	Counter:   <stored_counter>,
	PublicKey: <stored_publickey>,
}
newCounter, err := service.Verify(assertionObject, challenge, cliendData)
if err != nil {
    // handle error...
}
```
If the assertion is successful, get a new counter and save it.

## Testing

To accurately test the time-sensitive certificate validation logic, this project uses the `testtime` library. This library allows mocking the current time during tests.

**Note on Dates:** The `attestation` object in the JSON test data (`testdata/ios-14.4.json` or your custom `testdata/attestdata.json`) includes `validDate` and `expiredDate` fields. The tests use these dates with `testtime` to set the clock for certificate validation, allowing for consistent testing of both valid and expired certificate scenarios.

Run the following command to test.

```sh
go test -overlay=$(go run github.com/tenntenn/testtime/cmd/testtime@latest) ./...
```

When running the tests, the test runner will first look for a file named `testdata/attestdata.json`. If this file is present, it will be used as the source for test data. This is useful if you want to provide your own test data. If this file is not found, the test runner will fall back to using the default `testdata/ios-14.4.json` file.

### Generating Custom Test Data (Swift)

To create your own test data using Swift, follow these steps. This allows you to generate a JSON file containing attestation and assertion data that can be used for testing this Go package.

1.  **Implement the Swift code:** Use the provided Swift code snippet (or your own implementation) to generate the necessary attestation and assertion data.
2.  **Run on a physical device:** Execute the Swift code on a physical iOS device (not a simulator) to obtain valid App Attest data.
3.  **Save the output:** The Swift code will print a JSON string to the console. Copy this JSON output.
4.  **Save as `attestdata.json`:** Save the copied JSON string as a file named `attestdata.json` inside the `testdata/` directory of this project.

    *Note: If `testdata/attestdata.json` exists, the tests will use this file instead of `testdata/ios-14.4.json`.*

The Swift code for creating the test data looks like this:
###### Swift Package: AppAttest("https://github.com/iansampson/AppAttest")
```swift
import DeviceCheck
import CryptoKit
import AppAttest

func generate() async throws {
    let keyId = try await DCAppAttestService.shared.generateKey()
    let attestChallenge = Data(base64URLEncoded: "l5YkqI0Md8fmcBkw")!
     clientDataHash = Data(SHA256.hash(data: attestChallenge))
    let attest = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash)
    let attestRequest = AppAttest.AttestationRequest(attestation: attest, keyID: Data(base64Encoded: keyId)!)
    let appId = AppAttest.AppID(teamID: "AAJ6QYVL7U", bundleID: "org.sample.AttestSample")
    let result = try AppAttest.verifyAttestation(challenge: attestChallenge, request: attestRequest, appID: appId)

    let clientData = "{\"levelId\":\"1234\",\"action\":\"getGameLevel\",\"challenge\":\"bBjeLwdQD4KYRpzL\"}".data(using: .utf8)
    let assert = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: Data(SHA256.hash(data: clientData!)))
 
     print("""
{
    "attestation": {
        // Please refer to the "Attestation Fields" table below for the required JSON fields and their types.
    },
    "assertion": {
        // Please refer to the "Assertion Fields" table below for the required JSON fields and their types.
    }
""")
}
```

### Attestation Fields

| JSON Field Name | Type (JSON) | Description |
|---|---|---|
| `validDate` | `string` | Format: `YYYY-MM-DDTHH:mm:ss.SSSZ` (ISO 8601, compatible with `ISO8601DateFormatter` in Swift with `withFractionalSeconds` and `withInternetDateTime` options). Start date and time of certificate validity |
| `expiredDate` | `string` | Format: `YYYY-MM-DDTHH:mm:ss.SSSZ` (ISO 8601, compatible with `ISO8601DateFormatter` in Swift with `withFractionalSeconds` and `withInternetDateTime` options). Expiration date and time of certificate |
| `attestationBase64` | `string` | Base64 encoded data of the Attestation object |
| `clientDataHashSha256Base64` | `string` | Base64 encoded SHA256 hash of client data |
| `keyIdBase64` | `string` | Base64 encoded Key ID |
| `publicKey` | `string` | Public key in PEM format |
| `environment` | `string` | Environment (development/sandbox) |
| `teamIdentifier` | `string` | Team ID |
| `bundleIdentifier` | `string` | App's Bundle ID |

### Assertion Fields

| JSON Field Name | Type (JSON) | Description |
|---|---|---|
| `assertionBase64` | `string` | Base64 encoded data of the Assertion object |
| `clientDataBase64` | `string` | Base64 encoded client data |
| `challengeBase64` | `string` | Base64 encoded challenge |
| `publicKey` | `string` | Public key in PEM format |
| `counter` | `uint32` | Counter |
| `teamIdentifier` | `string` | Team ID |
| `bundleIdentifier` | `string` | App's Bundle ID |



## References

*   [DeviceCheck](https://developer.apple.com/documentation/devicecheck)
*   [Establishing your app's integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
*   [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
*   [Attestation Object Validation Guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide)
*   [Preparing to use the app attest service](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service)

## Acknowledgements

I referred to [appattest](https://github.com/bas-d/appattest) by Bas Doorn when creating this library. Their work was a valuable reference.


## Third-Party Attributions

This project uses `github.com/google/go-cmp` for comparing Go values in tests, which is licensed under the BSD 3-Clause License.

Test data used in this project is from [veehaitch/devicecheck-appattest](https://github.com/veehaitch/devicecheck-appattest), which is licensed under the Apache License 2.0.

This project uses `github.com/tenntenn/testtime` for time manipulation in tests, which is licensed under the BSD 3-Clause License.

## License
App-Attest is available under the MIT license. See the LICENSE file for more info.
