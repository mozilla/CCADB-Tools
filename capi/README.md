# CAPI
## Certificate Authority Publication of Information <br /> A tool for validating CA Browser Forum §2.2

This software enforces rules outlined in [CAB Forum Baseline Requirements §2.2](https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.5.9.pdf), wherein:

> The CA SHALL host test Web pages that allow Application Software Suppliers to test their software with Subscriber Certificates that chain up to each publicly trusted Root Certificate.  At a minimum, the CA SHALL host separate Web pages using Subscriber Certificates that are (i) valid, (ii) revoked, and (iii) expired.

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
##### 3. Installation into the NSS Database
- This program relies upon the [NSS Tools](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/tools) collection of utilities to perform chain validation and expiration checking. In order to use these tools, this program requires the use of an NSS database.
    - 3.a: In order to ensure sanity, each call to verify a single test website results in a private, completely empty, NSS database. That is, the only certificates present within the NSS database for a given test website are those constructed by step `2. Certificate Chain Construction`.
    - 3.b: Installation is done via the NSS tool, [certutil](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/tools/NSS_Tools_certutil).
    - 3.c: For every certificate within the chain constructed in `2. Certificate Chain Construction`, the following `cerutil` command is executed:
        ```
        If the certificate's issuer common name is equivalent to the certificate's subject common name (that is, the certificate is a trust anchor), then: 
            certutil -A -t C -n <CERT FINGERPRINT> -d <DATABASE DIRECTORY>
        else:
            certutil -A -t ,, -n <CERT FINGERPRINT> -d <DATABASE DIRECTORY>
        ```
##### 4. Expiration and Chain Verification
- Certificate expiration and chain verification is done via the NSS tool, `certutil`.
    - 4.a: For every certificate within the chain constructed in `2. Certificate Chain Construction`, the following `cerutil` command is executed:
        ```
        If the certificate is a CA, then:
            certutil -V -e -n <CERT FINGERPINT> -u L -d <DATABASE DIRECTORY>
        else:
            certutil -V -e -n <CERT FINGERPINT> -u V -d <DATABASE DIRECTORY>
        ```
    - 4.b: A certificate is identified as being a CA if its basic constraint of `cA` is set to true, as per [RFC 5280 4.2.1.9. Basic Constraints](https://tools.ietf.org/html/rfc5280#page-39).
    - 4.c: If `certutil` outputs `certutil: certificate is valid`, then that certificate is noted as being valid. Whether or not this results in a FAIL depends on which test suite (valid, revoked, expired) is being executed. For details, please see `Verification Rules`.
    - 4.d: If `certutil` outputs `certutil: certificate is invalid: Peer's Certificate has expired`, then that certificate is noted as being expired. Whether or not this results in a `FAIL` depends on which test suite (valid, revoked, expired) is being executed. For details, please see `Verification Rules`.
    - 4.e: If `certutil` outputs `certutil: certificate is invalid: Peer's Certificate issuer is not recognized`, then that certificate is marked as having a broken certificate chain. This will result in a `FAIL` for all test suites.
##### 5. CRL
- For a given certificate, all CRL endpoints are checked as follows.
    - 5.a: LDAP endpoints are _ignored_ by this program.
    - 5.b: A timeout of 20 seconds is enforced. If this 20-second timeout is triggered, then the test is marked as a `FAIL`
    - 5.c: HTTP requests from this client may be accurately identified from the following header: `"X-Automated-Tool": "https://github.com/mozilla/CCADB-Tools/capi CCADB test website verification tool"`
    - 5.d: CRL endpoints are extracted from the given certificate's `CRLDistributionPoints` as defined in [RFC 5280 4.2.1.13. CRL Distribution Points](https://tools.ietf.org/html/rfc5280#section-4.2.1.13).
    - 5.e: Every CRL downloaded is deserialized using the [Golang X509 ParseCRL](https://golang.org/pkg/crypto/x509/#ParseCRL) function.
    - 5.f: For each entry within the `revokedCertificates` sequence ([RFC 5280 5.1. CRL Fields](https://tools.ietf.org/html/rfc5280#section-5.1)) the `userCertificate` is compared with the given certificate's `serialNumber` ([RFC 5280 4.1. Basic Certificate Fields](https://tools.ietf.org/html/rfc5280#section-4.1)). If the serial number matches, then this certificate is considered `revoked` by this CRL.
    - 5.g: If no CRL distribution endpoints are listed within the certificate, or all endpoints serve an empty CRL, then this certificate is considered `good`.
    - 5.h: If there is a disagreement between CRLs on the status of a particular certificate, then this certificate will be marked as a `FAIL`.
##### 6. OCSP
- For a given certificate, all OCSP responders are checked as follows.
    - 6.a: OCSP responders are extracted from the given certificate's authority access information extension ([RFC 4.2.2.1. Authority Information Access](https://tools.ietf.org/html/rfc5280#section-4.2.2.1))
    - 6.b: Each OCSP responder listed is queried using a request generated by the [Golang crypto/ocsp](https://godoc.org/golang.org/x/crypto/ocsp) package.
    - 6.c: A timeout of 20 seconds is enforced. If this 20-second timeout is triggered, then the test is marked as a `FAIL`.
    - 6.d: HTTP requests from this client may be accurately identified from the following header: `"X-Automated-Tool": "https://github.com/mozilla/CCADB-Tools/capi CCADB test website verification tool"`
    - 6.e The statuses of `revoked`, `good`, or `unknown` (as per [RFC 2560](https://www.ietf.org/rfc/rfc2560.txt)) are recorded for a given certificate.

# Verification Rules
## Valid
A certificate chain, in the context of the `valid` test suite, is considered to pass [iff](https://en.wikipedia.org/wiki/If_and_only_if):
1. `certutil` outputs `certutil: certificate is valid` for all certificates within the candidate chain.
2. No certificate within the chain is listed as being revoked by any CRL listed within its `CRLDistributionPoints`.
3. No certificate within the chain is considered _not_ `good` by any OCSP responder listed within its authority information access.
## Expired
A certificate chain, in the context of the `expired` test suite, is considered to pass [iff](https://en.wikipedia.org/wiki/If_and_only_if):
1. `certutil` outputs `certutil: certificate is invalid: Peer's Certificate has expired` for the leaf certificate of the candidate chain.
2. The intermediate certificates within the candidate chain _may_ either be considered `valid` or `expired` by `certutil`
3. The root certificate _may not_ be considered `expired` by `certutil`.
4. The leaf certificate _must not_ be revoked by any CRL.
5. The leaf certificate _may be_ considered either `good` or `unauthorized` by OCSP responders.
5. No intermediate or root certificate within the chain may be revoked by any CRL.
6. No intermediate or root certificate within the chain is considered _not_ `good` by any OCSP responder listed within its authority information access.
## Revoked
A certificate chain, in the context of the `revoked` test suite, is considered to pass [iff](https://en.wikipedia.org/wiki/If_and_only_if):
1. `certutil` outputs `certutil: certificate is valid` for all certificates within the candidate chain.
2. The leaf certificate of the candidate chain is considered to be revoked by every CRL endpoint and OCSP responder.
3. The intermediate certificates within the candidate chain _may_ either be `revoked` or `good` with regard to their CRL endpoints and OCSP responders.
4. The root certificate _must_ be considered `good` by all OCSP responders and CRL endpoints.

## Linting

This tool supports linting certificate chains using the [x509lint](https://github.com/kroeckx/x509lint) tool and the [certlint](https://github.com/certlint/certlint) tool.

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
        "X509Lint": {
            "Errors": [],
            "Warnings": [],
            "Info": [
                "Subject has a deprecated CommonName"
            ],
            "CmdError": null // describes an error that resulted from running the tool itself. E.G. bad command line arguments
        },
        "Certlint": {
            "Certlint": {
                "Bug": [],
                "Info": [],
                "Notices": [],
                "Warnings": [],
                "Errors": [],
                "Fatal": [],
                "CmdError": null // describes an error that resulted from running the tool itself. E.G. bad command line arguments
            },
            "Cablint": {
                "Bug": [],
                "Info": [
                    "TLS Server certificate identified\tcertlint262274680"
                ],
                "Notices": [],
                "Warnings": [],
                "Errors": [],
                "Fatal": [],
                "CmdError": null // describes an error that resulted from running the tool itself. E.G. bad command line arguments
            }
        },
        "CrtSh": "https://crt.sh/?q=EE5778EE98C58D73D3EA555A26F381A610C71AF208CD024159BDE0646849DC64"
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

##### x509lint

The full list of possible error messages may be found [here](https://github.com/kroeckx/x509lint/blob/master/messages.c). All messages prefixed with `E:`, except for [`E: Fails decoding the characterset`](https://github.com/kroeckx/x509lint/blob/33c4b3bc36d2cd911d7eca7528c049c023031508/messages.c#L35) will result in a `FAIL` of that particular certificate.

All errors, warnings, and infos provided by x509lint are mapped directly to the `Errors`, `Warnings`, and `Info` arrays.

##### certlint

A description of the output of certlint (and its subtool, cablint) can be found [here](https://github.com/certlint/certlint#output). Any error messages marked as bug, error, or fatal will result in a `FAIL` of that particular certificate.

All bugs, info, notices, warnings, errors, and fatal output are mapped to the `Bug`, `Info`, `Notices`, `Warnings`, `Errors`, and `Fatal` arrays.
