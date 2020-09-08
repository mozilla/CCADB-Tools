EVChecker
-----------------

### Use Cases

EVChecker gets the EV Policy OIDs for each root cert listed in ExtendedValidation.cpp

This tool is used to fill in the “ExtendedValidation.cpp OIDs” fields on root certs in thee CCADB. There is a CCADB home page report that alerts when that field does not match the published “Mozilla EV Policy OID(s)” field.

The files in question are from [nightly](https://hg.mozilla.org/mozilla-central/raw-file/tip/security/certverifier/ExtendedValidation.cpp), [beta](https://hg.mozilla.org/releases/mozilla-beta/raw-file/tip/security/certverifier/ExtendedValidation.cpp), and [release](https://hg.mozilla.org/releases/mozilla-release/raw-file/tip/security/certverifier/ExtendedValidation.cpp) of Firefox.

### Deployment

#### Locally
When running `evChecker` locally:

        $ go build -o evChecker .
        $ PORT=8080 ./evChecker

#### Using Docker
Alternatively, one may use the provided `Dockerfile` and `Makefile`:

        $ make clean build run

### Usage

EVChecker offers four endpoints - `/release`, `/beta`, `nightly`, and `/?url=`

For example:

```bash
# Parse Firefox release.
curl http://localhost:8080/release

# Parse beta Firefox.
curl http://localhost:8080/beta

# Parse nightly Firefox
curl http://localhost:8080/nightly

# Parse niightly Firefox again, but with an explicit (read: arbirtrary) url parameter.
curl http://localhost:8080/?url=https://hg.mozilla.org/mozilla-central/raw-file/tip/security/certverifier/ExtendedValidation.cpp
```

Example output:

```json
{
  "Error": null,
  "EVInfos": [
    {
      "DottedOID": "1.3.6.1.4.1.6334.1.100.1",
      "OIDName": "Cybertrust EV OID",
      "SHA256Fingerprint": "960ADF0063E96356750C2965DD0A0867DA0B9CBD6E77714AEAFB2349AB393DA3",
      "Issuer": "CN=Cybertrust Global Root,O=Cybertrust\\, Inc",
      "Serial": "00000000000400000000010F85AA2D48"
    },
    {
      "DottedOID": "2.16.756.1.89.1.2.1.1",
      "OIDName": "SwissSign EV OID",
      "SHA256Fingerprint": "62DD0BE9B9F50A163EA0F8E75C053B1ECA57EA55C8688F647C6881F2C8357B95",
      "Issuer": "CN=SwissSign Gold CA - G2,O=SwissSign AG,C=CH",
      "Serial": "0000000000000000BB401C43F55E4FB0"
    },
    {
      "DottedOID": "2.16.840.1.114404.1.1.2.4.1",
      "OIDName": "Trustwave EV OID",
      "SHA256Fingerprint": "CECDDC905099D8DADFC5B1D209B737CBE2C18CFB2C10C0FF0BCF0D3286FC1AA2",
      "Issuer": "CN=XRamp Global Certification Authority,O=XRamp Security Services Inc,OU=www.xrampsecurity.com,C=US",
      "Serial": "50946CEC18EAD59C4DD597EF758FA0AD"
    },
    ...
    ...
    ...
    {
      "DottedOID": "2.23.140.1.1",
      "OIDName": "CA/Browser Forum EV OID",
      "SHA256Fingerprint": "657CFE2FA73FAA38462571F332A2363A46FCE7020951710702CDFBB6EEDA3305",
      "Issuer": "OU=certSIGN ROOT CA G2,O=CERTSIGN SA,C=RO",
      "Serial": "00000000000000110034B64EC6362D36"
    }
  ]
}
```