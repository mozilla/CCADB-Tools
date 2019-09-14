/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;

use crate::errors::*;
use reqwest::Url;
use std::convert::{TryFrom, TryInto};

use crate::model::Intermediary;
use base64;
use simple_asn1::ASN1Block::*;
use simple_asn1::*;
use x509_parser;

const _7BDA50131EA7E55C8FDDA63563D12314A7159D5621333BA8BCDAD0B8A3A50E6C: &[u8] = include_bytes!(
    "vendored_certs/7BDA50131EA7E55C8FDDA63563D12314A7159D5621333BA8BCDAD0B8A3A50E6C.crt"
);
const _A90F97D6B5C7612E020CBBCF0746200C9676E1828C5A850BE6BC888C345FA4B5: &[u8] = include_bytes!(
    "vendored_certs/A90F97D6B5C7612E020CBBCF0746200C9676E1828C5A850BE6BC888C345FA4B5.crt"
);
const _805A7B80601A6FFB4ABDE635EF47705EAE17620DEF9CFAF61462B62D7C4B886A: &[u8] = include_bytes!(
    "vendored_certs/805A7B80601A6FFB4ABDE635EF47705EAE17620DEF9CFAF61462B62D7C4B886A.crt"
);
const _7160A0D841B1C5C120A08C92DE2326483D90D9BFCE1984BDD6FF4AB6B7D273C3: &[u8] = include_bytes!(
    "vendored_certs/7160A0D841B1C5C120A08C92DE2326483D90D9BFCE1984BDD6FF4AB6B7D273C3.crt"
);
const _9C009CA2F97EA2CBF28173600DEF6F7A54C5664599B8AB500EE1885A56E4F270: &[u8] = include_bytes!(
    "vendored_certs/9C009CA2F97EA2CBF28173600DEF6F7A54C5664599B8AB500EE1885A56E4F270.crt"
);
const _01F8971121F4103D30BE4235CD7DC0EEE6C6AE12FCA7750848EA0E2E13FC2428: &[u8] = include_bytes!(
    "vendored_certs/01F8971121F4103D30BE4235CD7DC0EEE6C6AE12FCA7750848EA0E2E13FC2428.crt"
);

lazy_static! {
    static ref VENDORED_CERTS: HashMap<String, &'static [u8]> = [
        (
            "7BDA50131EA7E55C8FDDA63563D12314A7159D5621333BA8BCDAD0B8A3A50E6C".to_string(),
            _7BDA50131EA7E55C8FDDA63563D12314A7159D5621333BA8BCDAD0B8A3A50E6C
        ),
        (
            "A90F97D6B5C7612E020CBBCF0746200C9676E1828C5A850BE6BC888C345FA4B5".to_string(),
            _A90F97D6B5C7612E020CBBCF0746200C9676E1828C5A850BE6BC888C345FA4B5
        ),
        (
            "805A7B80601A6FFB4ABDE635EF47705EAE17620DEF9CFAF61462B62D7C4B886A".to_string(),
            _805A7B80601A6FFB4ABDE635EF47705EAE17620DEF9CFAF61462B62D7C4B886A
        ),
        (
            "7160A0D841B1C5C120A08C92DE2326483D90D9BFCE1984BDD6FF4AB6B7D273C3".to_string(),
            _7160A0D841B1C5C120A08C92DE2326483D90D9BFCE1984BDD6FF4AB6B7D273C3
        ),
        (
            "9C009CA2F97EA2CBF28173600DEF6F7A54C5664599B8AB500EE1885A56E4F270".to_string(),
            _9C009CA2F97EA2CBF28173600DEF6F7A54C5664599B8AB500EE1885A56E4F270
        ),
        (
            "01F8971121F4103D30BE4235CD7DC0EEE6C6AE12FCA7750848EA0E2E13FC2428".to_string(),
            _01F8971121F4103D30BE4235CD7DC0EEE6C6AE12FCA7750848EA0E2E13FC2428
        )
    ]
    .iter()
    .cloned()
    .collect();
}

const CCADB_URL: &str =
    "https://ccadb-public.secure.force.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV";

pub struct CCADBReport {
    pub report: Vec<CCADBEntry>,
}

impl CCADBReport {
    pub fn default() -> Result<CCADBReport> {
        CCADB_URL.parse::<Url>().unwrap().try_into()
    }

    pub fn from_reader<R: Read>(r: R) -> Result<CCADBReport> {
        let mut report: Vec<CCADBEntry> = vec![];
        let mut rdr = csv::Reader::from_reader(r);
        for entry in rdr.deserialize() {
            let record: CCADBEntry =
                entry.chain_err(|| "failed to deserialize a record from the CCADB")?;
            report.push(record)
        }
        Ok(CCADBReport { report })
    }
}

impl TryFrom<Url> for CCADBReport {
    type Error = Error;

    fn try_from(value: Url) -> Result<Self> {
        CCADBReport::from_reader(crate::http::new_get_request(value).send()?)
    }
}

impl TryFrom<&str> for CCADBReport {
    type Error = Error;

    fn try_from(url: &str) -> Result<Self> {
        url.parse::<Url>()
            .chain_err(|| format!("failed to parse {} to a valid URL", url))?
            .try_into()
    }
}

#[derive(Debug, Deserialize)]
pub struct CCADBEntry {
    #[serde(alias = "CA Owner")]
    pub ca_owner: String,
    #[serde(alias = "Revocation Status")]
    pub revocation_status: String,
    #[serde(alias = "RFC 5280 Revocation Reason Code")]
    pub rfc_5280_revocation_reason_code: String,
    #[serde(alias = "Date of Revocation")]
    pub date_of_revocation: String,
    #[serde(alias = "OneCRL Status")]
    pub one_crl_status: String,
    #[serde(alias = "Certificate Serial Number")]
    pub certificate_serial_number: String,
    #[serde(alias = "CA Owner/Certificate Name")]
    pub ca_owner_certificate_name: String,
    #[serde(alias = "Certificate Issuer Common Name")]
    pub certificate_issuer_common_name: String,
    #[serde(alias = "Certificate Issuer Organization")]
    pub certificate_issuer_organization: String,
    #[serde(alias = "Certificate Subject Common Name")]
    pub certificate_subject_common_name: String,
    #[serde(alias = "Certificate Subject Organization")]
    pub certificate_subject_organization: String,
    #[serde(alias = "SHA-256 Fingerprint")]
    pub sha_256_fingerprint: String,
    #[serde(alias = "Subject + SPKI SHA256")]
    pub subject_spki_sha_256: String,
    #[serde(alias = "Valid From [GMT]")]
    pub valid_from_gmt: String,
    #[serde(alias = "Valid To [GMT]")]
    pub valid_to_gmt: String,
    #[serde(alias = "Public Key Algorithm")]
    pub public_key_algorithm: String,
    #[serde(alias = "Signature Hash Algorithm")]
    pub signature_hash_algorithm: String,
    #[serde(alias = "CRL URL(s)")]
    pub crl_urls: String,
    #[serde(alias = "Alternate CRL")]
    pub alternate_crl: String,
    #[serde(alias = "OCSP URL(s)")]
    pub ocsp_urls: String,
    #[serde(alias = "Comments")]
    pub comments: String,
    #[serde(alias = "PEM Info")]
    pub pem_info: String,
}

impl Into<Option<Intermediary>> for CCADBEntry {
    fn into(self) -> Option<Intermediary> {
        let mut pem = self.pem_info.clone();
        match VENDORED_CERTS.get(&self.sha_256_fingerprint) {
            None => (),
            Some(cert) => {
                pem = String::from_utf8(Vec::from(*cert)).unwrap();
            }
        }
        if pem.len() == 0 {
            error!(
                "No PEM attached to certificate with serial {:?}",
                self.sha_256_fingerprint
            );
            return None;
        }
        let p = match x509_parser::pem::pem_to_der(pem.trim_matches('\'').as_bytes()) {
            Ok(thing) => thing,
            Err(err) => {
                error!(
                    "The following PEM failed to decode. err = {:?}, serial = {:?}",
                    err, self.sha_256_fingerprint
                );
                return None;
            }
        };
        let res = match p.1.parse_x509() {
            Ok(thing) => thing,
            Err(err) => {
                error!(
                    "The following x509 certificate failed to parse. err = {:?}, serial = {:?}",
                    err, self.sha_256_fingerprint
                );
                return None;
            }
        };
        let mut rdn: Vec<ASN1Block> = vec![];
        for block in res.tbs_certificate.issuer.rdn_seq {
            for attr in block.set {
                let oid = ObjectIdentifier(
                    1,
                    OID::new(
                        attr.attr_type
                            .iter()
                            .map(|val| BigUint::from(val.clone()))
                            .collect(),
                    ),
                );
                let content = match attr.attr_value.content {
                    der_parser::ber::BerObjectContent::PrintableString(s) => {
                        let s = std::str::from_utf8(s).unwrap();
                        PrintableString(s.len(), s.to_string())
                    }
                    der_parser::ber::BerObjectContent::UTF8String(s) => {
                        let s = std::str::from_utf8(s).unwrap();
                        UTF8String(s.len(), s.to_string())
                    }
                    der_parser::ber::BerObjectContent::IA5String(s) => {
                        let s = std::str::from_utf8(s).unwrap();
                        IA5String(s.len(), s.to_string())
                    }
                    der_parser::ber::BerObjectContent::T61String(s) => {
                        let s = std::str::from_utf8(s).unwrap();
                        TeletexString(s.len(), s.to_string())
                    }
                    val => {
                        error!(
                            "An unexpected BER content type was encountered when iterating \
                             of the issuer RDN of the certificate with serial {}. \
                             It's raw content is {:?}",
                            self.certificate_serial_number, val
                        );
                        return None;
                    }
                };
                rdn.append(&mut vec![Set(1, vec![Sequence(1, vec![oid, content])])]);
            }
        }
        let seq = Sequence(1, rdn);
        Some(Intermediary {
            issuer_name: base64::encode(&der_encode(&RDN { rdn: vec![seq] }).unwrap()),
            serial: base64::encode(&hex::decode(&self.certificate_serial_number).unwrap()),
        })
    }
}

struct RDN {
    rdn: Vec<ASN1Block>,
}

impl ToASN1 for RDN {
    type Error = Error;

    fn to_asn1_class(&self, _: ASN1Class) -> Result<Vec<ASN1Block>> {
        Ok(self.rdn.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        let c: CCADBReport = CCADB_URL.parse::<Url>().unwrap().try_into().unwrap();
        let _: Vec<Option<Intermediary>> = c.report.into_iter().map(|e| e.into()).collect();
    }

    #[test]
    fn into_intermediate() {
        let want = "MIGsMQswCQYDVQQGEwJFVTFDMEEGA1UEBxM6TWFkcmlkIChzZWUgY3VycmVudCBhZGRyZXNzI\
        GF0IHd3dy5jYW1lcmZpcm1hLmNvbS9hZGRyZXNzKTESMBAGA1UEBRMJQTgyNzQzMjg3MRswGQYDVQQKExJBQyBDYW1l\
        cmZpcm1hIFMuQS4xJzAlBgNVBAMTHkdsb2JhbCBDaGFtYmVyc2lnbiBSb290IC0gMjAwOA==";
        let entry = CCADBEntry {
            ca_owner: "".to_string(),
            revocation_status: "".to_string(),
            rfc_5280_revocation_reason_code: "".to_string(),
            date_of_revocation: "".to_string(),
            one_crl_status: "".to_string(),
            certificate_serial_number: "".to_string(),
            ca_owner_certificate_name: "".to_string(),
            certificate_issuer_common_name: "".to_string(),
            certificate_issuer_organization: "".to_string(),
            certificate_subject_common_name: "".to_string(),
            certificate_subject_organization: "".to_string(),
            sha_256_fingerprint: "".to_string(),
            subject_spki_sha_256: "".to_string(),
            valid_from_gmt: "".to_string(),
            valid_to_gmt: "".to_string(),
            public_key_algorithm: "".to_string(),
            signature_hash_algorithm: "".to_string(),
            crl_urls: "".to_string(),
            alternate_crl: "".to_string(),
            ocsp_urls: "".to_string(),
            comments: "".to_string(),
            pem_info: EXAMPLE.to_string(),
        };
        let entry: Option<Intermediary> = entry.into();
        let entry = entry.unwrap();
        assert_eq!(want.to_string(), entry.issuer_name)
    }

    const EXAMPLE: &str = r#"-----BEGIN CERTIFICATE-----
MIIIWjCCBkKgAwIBAgIIAahE5mpsDY4wDQYJKoZIhvcNAQELBQAwgawxCzAJBgNV
BAYTAkVVMUMwQQYDVQQHEzpNYWRyaWQgKHNlZSBjdXJyZW50IGFkZHJlc3MgYXQg
d3d3LmNhbWVyZmlybWEuY29tL2FkZHJlc3MpMRIwEAYDVQQFEwlBODI3NDMyODcx
GzAZBgNVBAoTEkFDIENhbWVyZmlybWEgUy5BLjEnMCUGA1UEAxMeR2xvYmFsIENo
YW1iZXJzaWduIFJvb3QgLSAyMDA4MB4XDTE4MDYyOTEwMjcxN1oXDTI1MDUxNjEw
MjcxN1owgacxCzAJBgNVBAYTAlBUMUIwQAYDVQQKDDlNVUxUSUNFUlQgLSBTZXJ2
acOnb3MgZGUgQ2VydGlmaWNhw6fDo28gRWxlY3Ryw7NuaWNhIFMuQS4xIDAeBgNV
BAsMF0NlcnRpZmljYXRpb24gQXV0aG9yaXR5MTIwMAYDVQQDDClNVUxUSUNFUlQg
U1NMIENlcnRpZmljYXRpb24gQXV0aG9yaXR5IDAwMTCCAiIwDQYJKoZIhvcNAQEB
BQADggIPADCCAgoCggIBAOTX1Zh09z52UHsBb4itNN1nHE4jmbvw4QxQP6JzPBE2
HYL0N3RDqIUc7jEiOgTMN90w2Z+2p40BUrpWS0+sIRcZl14McSrzIUjLAqHu6n6Z
yDfRzAJtlhkoKXprimqVXI0zQkFRBGrO9SfPOqnciBytMv6CyRV19vwIjyS21+tv
zhId401J5ab/weycKRi0V2ki4V1vPOIkW2ygqXSAz8XwLObvhTdyETHZCFEpge7v
czc2HCTLQ90iJcTEy0DYmQU5j05KuYsHp7g0tc9UH0X+I/LEQqqSv9k4B8RYTgzP
5QU7aG/85Lu8Jbb2Rce+Rf2uuKds2XVmqhKb/k4OQ057unOy9EKVRsqA012ofyEU
IJSixdSaF/Bz8qtCxX6Qeyvjjk5a2k93xdr/DoDJdRv60YWwbkNVCk9gj6CttbF8
m2YHuVaOxCjo79/pzTnsgBZf2/C0thKdctuzvkXy75Fa1Oa20BXDDVSHQGg4iuex
cyEr98nraAGm1sFkzcaRprtwNCjyrYNdlehLehamzZOU9+y+0v4qZGfBLpRz8Ac0
BJf7NdfUIUiZ8GhwJ3Ml9mhdG+ND0P+LhtAiI9m3MnAkNoAHS1VAQGgshp4TAew3
vvuSKvZ9Eb7ct9vz5c5YPZ6Y70bE14wlqpu4ZlDbb+KaMZa2CNHAMuCFmuCjW9Cb
AgMBAAGjggKBMIICfTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSwAjlS
Ck9zmsjZgUU2XRGdXyM5lzCB4QYDVR0jBIHZMIHWgBS5CcqcHtvTbDprru1U8VuT
BjUuXqGBsqSBrzCBrDELMAkGA1UEBhMCRVUxQzBBBgNVBAcTOk1hZHJpZCAoc2Vl
IGN1cnJlbnQgYWRkcmVzcyBhdCB3d3cuY2FtZXJmaXJtYS5jb20vYWRkcmVzcykx
EjAQBgNVBAUTCUE4Mjc0MzI4NzEbMBkGA1UEChMSQUMgQ2FtZXJmaXJtYSBTLkEu
MScwJQYDVQQDEx5HbG9iYWwgQ2hhbWJlcnNpZ24gUm9vdCAtIDIwMDiCCQDJzdPp
1X0jzjB9BggrBgEFBQcBAQRxMG8wRQYIKwYBBQUHMAKGOWh0dHA6Ly93d3cuY2Ft
ZXJmaXJtYS5jb20vY2VydHMvcm9vdF9jaGFtYmVyc2lnbi0yMDA4LmNydDAmBggr
BgEFBQcwAYYaaHR0cDovL29jc3AuY2FtZXJmaXJtYS5jb20wDgYDVR0PAQH/BAQD
AgEGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMEAGA1UdIAQ5MDcwNQYGZ4EMAQICMCsw
KQYIKwYBBQUHAgEWHWh0dHBzOi8vcG9saWN5LmNhbWVyZmlybWEuY29tMH4GA1Ud
HwR3MHUwOKA2oDSGMmh0dHA6Ly9jcmwuY2FtZXJmaXJtYS5jb20vY2hhbWJlcnNp
Z25yb290LTIwMDguY3JsMDmgN6A1hjNodHRwOi8vY3JsMS5jYW1lcmZpcm1hLmNv
bS9jaGFtYmVyc2lnbnJvb3QtMjAwOC5jcmwwDQYJKoZIhvcNAQELBQADggIBAKdP
wQQn3wavGQPmEmKxBDbB3eH9JoFSb2LOtCaqX0ucYcJL5YRfD6zSL/nyv321Pgf1
GCByll1pJ1IMEySzdYxwsDYwiHP2U8pHrLzhMbMRrvUNFTzOt+ShzySa4sd88x7n
UtbwdGMaDZpGnhXv8rnUlaQ6XH4BTCxzIsqVePK9DyxlNuD4IORWjAkkc3Qdi76k
XzE027IsJE8G4uyP7AGhocqr21vSxsfYevtHuhmw5Sl7jLExPrBUD8XP8YQhMDD7
kpPv96JhlkkpuTEAUJGDHcnfCLr9kp6VTZMfFPO5xcpZ8SLJBOq4nwDG69m9te/+
MqtVv5Y4HB+E5H3/YKdK+pzQ9LNCGfXNgx8fssRaHn52FuYpRpumgABuk3Ynr1+v
0XUIh4rh/BtAbnGQWkbdF5Qo0OvFv7cx5Y52Ml3q1B1JIq0NV7qqxxi/IvQrfwrp
bW1Tzop9gbafWQX0g/JdaHBVJSngo76e7wEoOisvU7yrWuleyTSf+UjJFYxH7gBz
X4FJlpsRkl3PNzxr0GNOGkC/0CfAfP/+nXs09o92ZIyWyUTliyTqn5xpcL6G/wR8
8n7YM0TwiqPOW+VGbIaPsqzpL0zqDXk37K+mZv1dMxtn1W/77vC3vLWg8/WsyIph
AvMUz+wbPfDMWThnRmTw+U3Wz2tflWlhkDgHYcrs
-----END CERTIFICATE-----"#;

    const BAD_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIEbTCCA1WgAwIBAgIRALxyZmb/WL/wAuUiPK5oK/gwDQYJKoZIhvcNAQELBQAw
PjELMAkGA1UEBhMCUEwxGzAZBgNVBAoTElVuaXpldG8gU3AuIHogby5vLjESMBAG
A1UEAxMJQ2VydHVtIENBMBwXCzEyMDIwMTAxNTlaFw0yMDExMDIwMTAxNTlaMFgx
CzAJBgNVBAYTAkNOMRowGAYDVQQKExFXb1NpZ24gQ0EgTGltaXRlZDEtMCsGA1UE
AxMkQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgb2YgV29TaWduIEcyMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvsXEoCKASU+/2YcRxlPhuw+9YH+v9oIO
H9ywjj2X4FA8jzrvZjtFB5sg+OPXJYY1kBaiXW8wGQiHC38Gsp1ij96vkqVg1CuA
mlI/9ZqD6TRay9nVYlzmDuDfBpgOgHzKtB0TiGsOqCR3A9DuW/PKaZE1OVbFbeP3
PU9ekzgkyhjpJMuSA93MHD0JcOQg5PGurLtzaaNjOg9FD6FKmsLRY6zLEPg95k4o
t+vElbGs/V6r+kHLXZ1L3PR8du9nfwB6jdKgGlxNIuG12t12s9R23164i5jIFFTM
axeSt+BKv0mUYQs4kI9dJGwlezt52eJ+na2fmKEG/HgUYFf47oB3sQIDAQABo4IB
TDCCAUgwEgYDVR0TAQH/BAgwBgEB/wIBAjAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0O
BBYEFPpgqetlxd0WFAhODA+Nm+D3ZK9nMFIGA1UdIwRLMEmhQqRAMD4xCzAJBgNV
BAYTAlBMMRswGQYDVQQKExJVbml6ZXRvIFNwLiB6IG8uby4xEjAQBgNVBAMTCUNl
cnR1bSBDQYIDAQAgMDkGA1UdHwQyMDAwLqAsoCqGKGh0dHA6Ly93b3NpZ24uY3Js
LmNlcnR1bS5ldS9jZXJ0dW1jYS5jcmwwOAYIKwYBBQUHAQEELDAqMCgGCCsGAQUF
BzABhhxodHRwOi8vc3ViY2Eub2NzcC1jZXJ0dW0uY29tMDoGA1UdIAQzMDEwLwYE
VR0gADAnMCUGCCsGAQUFBwIBFhlodHRwczovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0G
CSqGSIb3DQEBCwUAA4IBAQBzFbBroKWp4Bv12bVYJiRnpYXNNAh9jBsb/oHCw+I5
wX3khi5vbKW4Kp55w3oFB4oFYKK2FmZrDZV5/TUNgxHTtlP+Ge/gs8lkk6f6QW5D
ZN5JVVR/u4gmZdJmCC9eRoJsc3TgiH5ZGxLOtqXi3GR8hIAJVIbkqHrbfA7YAUua
+IQP1MiL/mr08Ceq6NQY6jYD3ovJ9bx6sPSghn41TdnQL5Y2Ze7qayrh9cl5zVpU
78CK9A6XG/zYcGdgC2wAAtOpobNsmFPJ0NR4EW7igvCq8VbKuCNIaUD6e2qOjGAA
MrLquF5zoh4cdCw6X5o7HnYSEdfHxZuQ//FoIkEauUGp
-----END CERTIFICATE-----"#;

    #[test]
    fn bad_cert() {
        let p = x509_parser::pem::pem_to_der(BAD_CERT.trim_matches('\'').as_bytes()).unwrap();
        p.1.parse_x509().unwrap();
    }
}
