# ev-checker #
******
## *Note (2023-08-18) ##
*This source code was copied from the `mozilla-services/ev-checker` repo here:
https://github.com/mozilla-services/ev-checker/tree/04a7d03ff8ba4a3965bbd50c1d494100d99b8138
This was done to prevent upstream dependency issues. The original source code is under the MPL 2.0 license.*

---

## What ##
`ev-checker` is a standalone command-line utility for determining if a given EV
policy fulfills the requirements of Mozilla's Root CA program and may thus be
enabled.

## How ##
`ev-checker` depends on the libraries
[NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) and
[NSPR](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSPR). It
additionally makes use of
[mozilla::pkix](https://wiki.mozilla.org/SecurityEngineering/Certificate_Verification).
Since mozilla::pkix has not been released as a stand-alone library yet, this
project imports a snapshot of the implementation. (See the file `pkix-import`.)
`ev-checker` implements a `mozilla::pkix::TrustDomain` and uses
`mozilla::pkix::BuildCertChain` to determine if a given EV policy meets the
requirements to be enabled in Firefox.

## Example ##
First, compile with `make`. There is no guarantee of portability, so feel free
to file issues if this does not work as expected.

Then, given the file `cert-chain.pem`, the dotted OID of the EV policy, and a
hostname to validate against, run `ev-checker` like so:

`./ev-checker -c cert-chain.pem -o dotted.OID -h hostname`

`-c` specifies the file containing a sequence of PEM-encoded certificates. The
first certificate is the end-entity certificate intended to be tested for EV
treatment. The last certificate is the root certificate that is authoritative
for the given EV policy. Any certificates in between are intermediate
certificates.

If run with the flag `-d` and a description of the EV OID, `ev-checker` will
output a blob of text that must be added to
[security/certverifier/ExtendedValidation.cpp](https://dxr.mozilla.org/mozilla-central/source/security/certverifier/ExtendedValidation.cpp)
in the mozilla-central tree for Firefox to consider this a valid EV policy.
It will also validate the end-entity certificate. If it succeeds, the EV policy
is ready to be enabled. If not, something needs to be fixed.
Hopefully `ev-checker` emitted a helpful error message pointing to the problem.

```bash
$ ev-checker -c chain.pem -o 2.16.840.1.114412.2.1 -d "Digicert EV OID" -h addons.mozilla.org

// CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
"2.16.840.1.114412.2.1",
"Digicert EV OID",
SEC_OID_UNKNOWN,
{ 0x74, 0x31, 0xE5, 0xF4, 0xC3, 0xC1, 0xCE, 0x46, 0x90, 0x77, 0x4F,
  0x0B, 0x61, 0xE0, 0x54, 0x40, 0x88, 0x3B, 0xA9, 0xA0, 0x1E, 0xD0,
  0x0B, 0xA6, 0xAB, 0xD7, 0x80, 0x6E, 0xD3, 0xB1, 0x18, 0xCF },
"MGwxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT"
"EHd3dy5kaWdpY2VydC5jb20xKzApBgNVBAMTIkRpZ2lDZXJ0IEhpZ2ggQXNzdXJh"
"bmNlIEVWIFJvb3QgQ0E=",
"AqxcJmoLQJuPC3nyrkYldw==",
Success!
```

## TODO Items ##
* Do OCSP fetching
* Other policy issues
* More helpful error messages
