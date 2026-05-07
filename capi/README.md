# CAPI
## Certificate Authority Publication of Information <br /> A tool for validating CA Browser Forum §2.2

This software enforces rules outlined in [CAB Forum Baseline Requirements §2.2](https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.5.9.pdf), wherein:

> The CA SHALL host test Web pages that allow Application Software Suppliers to test their software with Subscriber Certificates that chain up to each publicly trusted Root Certificate.  At a minimum, the CA SHALL host separate Web pages using Subscriber Certificates that are (i) valid, (ii) revoked, and (iii) expired.

## Usage

Build:
```sh
docker build .
docker run -p 8080:8080 capi
```
Example TESTINFO:
```sh
TESTINFO=$(cat <<EOF
{ "CertificateDetails":[ { "RecordID":"234571894056781356", "Name":"SSL.com Root Certification Authority ECC", "PEM":"-----BEGIN CERTIFICATE----- MIICjTCCAhSgAwIBAgIIdebfy8FoW6gwCgYIKoZIzj0EAwIwfDELMAkGA1UEBhMC VVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMRgwFgYDVQQKDA9T U0wgQ29ycG9yYXRpb24xMTAvBgNVBAMMKFNTTC5jb20gUm9vdCBDZXJ0aWZpY2F0 aW9uIEF1dGhvcml0eSBFQ0MwHhcNMTYwMjEyMTgxNDAzWhcNNDEwMjEyMTgxNDAz WjB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0 b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8GA1UEAwwoU1NMLmNvbSBS b290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IEVDQzB2MBAGByqGSM49AgEGBSuB BAAiA2IABEVuqVDEpiM2nl8ojRfLliJkP9x6jh3MCLOicSS6jkm5BBtHllirLZXI 7Z4INcgn64mMU1jrYor+8FsPazFSY0E7ic3s7LaNGdM0B9y7xgZ/wkWV7Mt/qCPg CemB+vNH06NjMGEwHQYDVR0OBBYEFILRhXMw5zUE044CkvvlpNHEIejNMA8GA1Ud EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUgtGFczDnNQTTjgKS++Wk0cQh6M0wDgYD VR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA2cAMGQCMG/n61kRpGDPYbCWe+0F+S8T kdzt5fxQaxFGRrMcIQBiu77D5+jNB5n5DQtdcj7EqgIwH7y6C+IwJPt8bYBVCpk+ gA0z5Wajs6O7pdWLjwkspl1+4vAHCGht0nxpbl/f5Wpl -----END CERTIFICATE-----", "TestWebsiteValid":"https://test-dv-ecc.ssl.com", "TestWebsiteRevoked":"https://revoked-ecc-dv.ssl.com", "TestWebsiteExpired":"https://expired-ecc-dv.ssl.com" } ] }
EOF
)
```
Run the full test suite on TESTINFO:
```sh
curl -X POST -H "Content-Type: application/json" --data "$TESTINFO" http://127.0.0.1:8080/fromCertificateDetails
```

## Use Cases
This tool runs tests to verify that the three sample websites required by the CAB Forum Baseline Requirements (for valid, expired, and revoked certificates) do in fact chain up to the specified root certificate and that the status of TLS certificates are as expected (valid, expired, or revoked). Lint tests are also ran against the specified sample website TLS certificates.

This tool is used by Audit Cases and Root Inclusion Cases in the CCADB.

#### Precondition
Given the input of a candidate root certificate and three test websites, the following tests are executed.

#### Execution
##### 1. Certificate Chain Download
- `HTTP GET` is called on the target URL and the provided certificate chain is extracted from the response.
    - 1.a: The content of the website is otherwise ignored.
    - 1.b: A timeout of 20 seconds is enforced. If this 20-second timeout is triggered, then the test is marked as a `FAIL`.
    - 1.c: The client used to connect to the target website is the [Golang HTTP Client](https://golang.org/pkg/net/http/) with TLS verification disabled.
    - 1.d: HTTP requests from this client may be accurately identified from the following header: `"X-Automated-Tool": "https://github.com/mozilla/CCADB-Tools/capi CCADB test website verification tool"`
##### 2. Certificate Chain Construction
- The `candidate root certificate` is emplaced as the root of the certificate chain offered by the target website.
    - 2.a: If the target website fails to provide _all_ intermediate certificates, then this test will be marked as a `FAIL` during certificate chain validation. For details, please see `Verification Rules`.
    - 2.b: If the target website does not provide a root certificate within its chain, then the `candidate root certificate` is installed to the chain as the root.
    - 2.c: If the target webiste *_does_* provide a root certificate within its chain, then that certificate is discarded and the `candidate root certificate` is installed to the chain as the root.
##### 3. Expiration and Chain Verification
- Chain and expiration checking is done with the Go standard library's [`crypto/x509`](https://pkg.go.dev/crypto/x509) package.
    - 3.a: Each verification operates on a private trust set built only from the chain constructed in `2. Certificate Chain Construction`. Self-issued certificates (those whose subject DER equals their issuer DER) are placed in the roots pool; all others go in the intermediates pool.
    - 3.b: For every certificate within the chain, the following classification is produced:
        - If the certificate's `notAfter` is in the past, it is recorded as `expired`.
        - Otherwise, if the certificate is self-issued, its self-signature is verified. The certificate is recorded as `valid` if the signature checks out, including the case where Go reports `x509.InsecureAlgorithmError` (legacy signature algorithms such as SHA1WithRSA are accepted for trust-anchor self-signatures). A genuinely invalid self-signature is recorded as `issuerUnknown`.
        - Otherwise, `Certificate.Verify` is called with the chain-derived roots and intermediates pools, `KeyUsages` set to `ExtKeyUsageAny`, and `CurrentTime` pinned inside the certificate's own validity window. Success is recorded as `valid`; failure is recorded as `issuerUnknown`.
    - 3.c: Pinning `CurrentTime` to the certificate under test means an expired ancestor surfaces as `issuerUnknown` for the descendant rather than being attributed to the descendant as expiration.
##### 4. CRL
- For a given certificate, all CRL endpoints are checked as follows.
    - 4.a: LDAP endpoints are _ignored_ by this program.
    - 4.b: A timeout of 20 seconds is enforced. If this 20-second timeout is triggered, then the test is marked as a `FAIL`
    - 4.c: HTTP requests from this client may be accurately identified from the following header: `"X-Automated-Tool": "https://github.com/mozilla/CCADB-Tools/capi CCADB test website verification tool"`
    - 4.d: CRL endpoints are extracted from the given certificate's `CRLDistributionPoints` as defined in [RFC 5280 4.2.1.13. CRL Distribution Points](https://tools.ietf.org/html/rfc5280#section-4.2.1.13).
    - 4.e: Every CRL downloaded is deserialized using the [Golang X509 ParseCRL](https://golang.org/pkg/crypto/x509/#ParseCRL) function.
    - 4.f: For each entry within the `revokedCertificates` sequence ([RFC 5280 5.1. CRL Fields](https://tools.ietf.org/html/rfc5280#section-5.1)) the `userCertificate` is compared with the given certificate's `serialNumber` ([RFC 5280 4.1. Basic Certificate Fields](https://tools.ietf.org/html/rfc5280#section-4.1)). If the serial number matches, then this certificate is considered `revoked` by this CRL.
    - 4.g: If no CRL distribution endpoints are listed within the certificate, or all endpoints serve an empty CRL, then this certificate is considered `good`.
    - 4.h: If there is a disagreement between CRLs on the status of a particular certificate, then this certificate will be marked as a `FAIL`.
##### 5. OCSP
- For a given certificate, all OCSP responders are checked as follows.
    - 5.a: OCSP responders are extracted from the given certificate's authority access information extension ([RFC 4.2.2.1. Authority Information Access](https://tools.ietf.org/html/rfc5280#section-4.2.2.1))
    - 5.b: Each OCSP responder listed is queried using a request generated by the [Golang crypto/ocsp](https://godoc.org/golang.org/x/crypto/ocsp) package.
    - 5.c: A timeout of 20 seconds is enforced. If this 20-second timeout is triggered, then the test is marked as a `FAIL`.
    - 5.d: HTTP requests from this client may be accurately identified from the following header: `"X-Automated-Tool": "https://github.com/mozilla/CCADB-Tools/capi CCADB test website verification tool"`
    - 5.e The statuses of `revoked`, `good`, or `unknown` (as per [RFC 2560](https://www.ietf.org/rfc/rfc2560.txt)) are recorded for a given certificate.

# Verification Rules
## Valid
A certificate chain, in the context of the `valid` test suite, is considered to pass [iff](https://en.wikipedia.org/wiki/If_and_only_if):
1. Every certificate within the candidate chain is recorded as `valid` by the chain verification step.
2. No certificate within the chain is listed as being revoked by any CRL listed within its `CRLDistributionPoints`.
3. No certificate within the chain is considered _not_ `good` by any OCSP responder listed within its authority information access.
## Expired
A certificate chain, in the context of the `expired` test suite, is considered to pass [iff](https://en.wikipedia.org/wiki/If_and_only_if):
1. The leaf certificate of the candidate chain is recorded as `expired` by the chain verification step.
2. The intermediate certificates within the candidate chain _may_ be recorded as either `valid` or `expired`.
3. The root certificate _may not_ be recorded as `expired`.
4. The leaf certificate _must not_ be revoked by any CRL.
5. The leaf certificate _may be_ considered either `good` or `unauthorized` by OCSP responders.
5. No intermediate or root certificate within the chain may be revoked by any CRL.
6. No intermediate or root certificate within the chain is considered _not_ `good` by any OCSP responder listed within its authority information access.
## Revoked
A certificate chain, in the context of the `revoked` test suite, is considered to pass [iff](https://en.wikipedia.org/wiki/If_and_only_if):
1. Every certificate within the candidate chain is recorded as `valid` by the chain verification step.
2. The leaf certificate of the candidate chain is considered to be revoked by every CRL endpoint and OCSP responder.
3. The intermediate certificates within the candidate chain _may_ either be `revoked` or `good` with regard to their CRL endpoints and OCSP responders.
4. The root certificate _must_ be considered `good` by all OCSP responders and CRL endpoints.

## Linting

This tool supports linting certificate chains using the various linters that are integrated into the [pkimetal](https://github.com/pkimetal/pkimetal) meta-linter.

The following three endpoints are provided:
	
1. `/lintFromReport` takes no arguments and no body, and returns lint results for the entire [IncludedCACertificateReportPEMCSV](https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV) report. 
2. `/lintFromCertificateDetails` takes no arguments but takes a body which is a JSON array of the following struct:
    ```go
    type CCADBRecord struct {
        RecordID           string
        Name               string
        PEM                string
        TestWebsiteValid   string
        TestWebsiteRevoked string
        TestWebsiteExpired string
    }
    ```
3. `/lintFromSubject/?subject=<TEST WEBSITE URL>` takes one argument which is the URL of the target test website and no body.

For each test website submitted, linters are ran against all certificates within the the target certificate chain _except_ for the root certificate.

#### Linter Return

The following is an example JSON structure of a single linter result. If an endpoint returns multiple results (E.G. `/lintFromReport`), then the client will receive a JSON array of these objects.

```json
{
    "Subject": "https://ssltest-active.actalis.it/",
    "Leaf": {
        "PkiMetal": {
            "Info": [
                "[badkeys] Key ok",
                "[certlint] TLS Server certificate identified",
                "[ctlint] Certificate with embedded SCT list identified",
                "[ctlint] SCT has a valid signature from DigiCert Sphinx 2026h2",
                "[ctlint] SCT has a valid signature from Google Xenon 2026h2",
                "[ctlint] SCT has a valid signature from Sectigo Mammoth 2026h2",
                "[dwklint] Public Key is not a Debian weak key",
                "[ftfy] ftfy not invoked, because Subject DN only contains printable ASCII characters",
                "[pkilint] pkix.subject_key_identifier_method_1_identified (certificate.tbsCertificate.extensions.7.extnValue.subjectKeyIdentifier) - The Subject key identifier was calculated using the first algorithm defined in RFC 5280",
                "[pwnedkeys] Public Key is not pwned",
                "[rocacheck] Public Key is not a ROCA weak key",
                "[x509lint] Checking as leaf certificate",
                "[x509lint] Subject has a deprecated CommonName"
            ],
            "Notice": [],
            "Warning": [
                "[pkilint] cabf.serverauth.subscriber.subject_key_identifier_extension_present (certificate.tbsCertificate.extensions) - A discouraged element is present",
                "[pkilint] cabf.serverauth.ov.common_name_attribute_present (certificate.tbsCertificate.subject.rdnSequence) - A discouraged element is present",
                "[pkilint] cabf.serverauth.subscriber_first_policy_oid_not_reserved (certificate.tbsCertificate.extensions.4.extnValue.certificatePolicies) - Validates that the certificate policy OID(s) conform to BR 7.1.2.7.9.",
                "[pkilint] cabf.serverauth.subscriber_rsa_digitalsignature_and_keyencipherment_present (certificate.tbsCertificate.extensions.8.extnValue.keyUsage) - Validates that the content of the key usage extension conforms with BR 7.1.2.7.11.",
                "[pkilint] cabf.serverauth.certificate_policy_qualifier_present (certificate.tbsCertificate.extensions.4.extnValue.certificatePolicies.0.policyQualifiers.0) - Validates that the inclusion of policy qualifiers is in conformance with BR 7.1.2.3.2, 7.1.2.10.5, and 7.1.2.7.9.",
                "[zlint] w_subject_common_name_included - Subscriber Certificate: commonName is NOT RECOMMENDED.",
                "[zlint] w_ext_subject_key_identifier_not_recommended_subscriber - Subscriber certificates use of Subject Key Identifier is NOT RECOMMENDED"
            ],
            "Error": [],
            "Bug": [],
            "Fatal": [],
            "CmdError": null // describes an error that resulted from running the tool itself. E.G. bad command line arguments
        },
        "CrtSh": "https://crt.sh/?q=9324C7E7E563CF13E87BB3D6C0FA6A57BA2B35D3DE8B72908BD309F24702B08F"
    },
    "Intermediates": [],
    "Opinion": {
        "Result": "PASS",
        "Errors": []
    },
    "Error": "" // describes an error when executing the request itself rather than an error about linting
}
```

#### Interpreting Linter Results

See documentation for each of the [supported linters](https://github.com/pkimetal/pkimetal?tab=readme-ov-file#supported-linters).

Any linter finding with a severity of `fatal`, `bug`, or `error`, will result in a `FAIL` of that particular certificate.
