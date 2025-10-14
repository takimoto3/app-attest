# App-Attest
[![](https://img.shields.io/badge/go-%3E%3D%201.23-blue)](#Installation)

App-Attest is a go package implements the server-side validation of both attestations and assertions that can be obtained using the [DCAppAttestService](https://developer.apple.com/documentation/devicecheck/dcappattestservice).
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
var keyID = []byte(.....) // DCAppAttestService.generateKey returned value and base64.StdEncoding.DecodeString
var challenge = []byte(.....) // one-time challenge from the server
var clientDataHash = sha256.Sum256(challenge)
var attestation = []byte(.....) // DCAppAttestService.attestKey returned value

attestationObj := &attest.AttestationObject{}
err := attestationObj.Unmarshal(attestation)
if err != nil {
    // handle error...
}
service := attest.AttestationService{
    PathForRootCA: "testdata/Apple_App_Attestation_Root_CA.pem",
    AppID: "<TEAM ID>.<Bundle ID>",
}
result, err := service.Verify(attestObject, clientDataHash[:], keyID)
if err != nil {
    // handle error...
}

// use result ....
```

The Verify function return attest.Result(contain the public key and receipt and enviroment) if the validation succeeds. The public key and receipt should be save.

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
If the assertion is successful, get a new counter and save it

### Testing

The certificate contained in the attestation has a short expiration date, and you should have an up-to-date attestation to run the test.

#### Swift
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
  "appID": "\(appId.teamID).\(appId.bundleID)",
  "keyID": "\(keyId)",
  "attestation": "\(attest.base64EncodedString())",
  "publicKey": "\(result.publicKey.rawRepresentation.map{ String(format: "%02hhx", $0)}.joined())",
  "assertion": "\(assert.base64EncodedString())"
}
""")
}
```
Run it on the actual machine instead of the simulator and save the output of the XCode console as a test file.
* testdata/attestation.json
* testdata/attestation_expired.json (Old file)

Finally run test

## Acknowledgements

I referred to [appattest](https://github.com/bas-d/appattest) by Bas Doorn when creating this library. thanks!


## Third-Party Attributions

This project uses `github.com/brianolson/cbor_go` for CBOR encoding/decoding, which is licensed under the Apache License 2.0.

## License
App-Attest is available under the MIT license. See the LICENSE file for more info.
