use serde::Deserialize;
use std::io::Read;

use crate::errors::*;
use crate::model::Intermediary;
use reqwest::Url;
use std::convert::{TryFrom, TryInto};

use base64;
use simple_asn1::ASN1Block::*;
use simple_asn1::*;
use x509_parser;

const CCADB_URL: &str =
    "https://ccadb-public.secure.force.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV";

struct CCADBReport {
    pub report: Vec<CCADBEntry>,
}

impl CCADBReport {
    pub fn from_reader<R: Read>(r: R) -> Result<CCADBReport> {
        let mut report: Vec<CCADBEntry> = vec![];
        let mut rdr = csv::Reader::from_reader(r);
        for entry in rdr.deserialize() {
            let record = match entry {
                Ok(val) => val,
                Err(err) => panic!(format!("{:?}", err)),
            };
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
struct CCADBEntry {
    #[serde(alias = "CA Owner")]
    ca_owner: String,
    #[serde(alias = "Revocation Status")]
    revocation_status: String,
    #[serde(alias = "RFC 5280 Revocation Reason Code")]
    rfc_5280_revocation_reason_code: String,
    #[serde(alias = "Date of Revocation")]
    date_of_revocation: String,
    #[serde(alias = "OneCRL Status")]
    one_crl_status: String,
    #[serde(alias = "Certificate Serial Number")]
    certificate_serial_number: String,
    #[serde(alias = "CA Owner/Certificate Name")]
    ca_owner_certificate_name: String,
    #[serde(alias = "Certificate Issuer Common Name")]
    certificate_issuer_common_name: String,
    #[serde(alias = "Certificate Issuer Organization")]
    certificate_issuer_organization: String,
    #[serde(alias = "Certificate Subject Common Name")]
    certificate_subject_common_name: String,
    #[serde(alias = "Certificate Subject Organization")]
    certificate_subject_organization: String,
    #[serde(alias = "SHA-256 Fingerprint")]
    sha_256_fingerprint: String,
    #[serde(alias = "Subject + SPKI SHA256")]
    subject_spki_sha_256: String,
    #[serde(alias = "Valid From [GMT]")]
    valid_from_gmt: String,
    #[serde(alias = "Valid To [GMT]")]
    valid_to_gmt: String,
    #[serde(alias = "Public Key Algorithm")]
    public_key_algorithm: String,
    #[serde(alias = "Signature Hash Algorithm")]
    signature_hash_algorithm: String,
    #[serde(alias = "CRL URL(s)")]
    crl_urls: String,
    #[serde(alias = "Alternate CRL")]
    alternate_crl: String,
    #[serde(alias = "OCSP URL(s)")]
    ocsp_urls: String,
    #[serde(alias = "Comments")]
    comments: String,
    #[serde(alias = "PEM Info")]
    pem_info: String,
}

impl TryInto<Option<Intermediary>> for CCADBEntry {
    type Error = Error;

    fn try_into(self) -> Result<Option<Intermediary>> {
        if self.pem_info.len() == 0 {
            eprintln!("0: {:?}", self.certificate_serial_number);
            return Ok(None);
        }
        let p = match x509_parser::pem::pem_to_der(self.pem_info.trim_matches('\'').as_bytes()) {
            Ok(thing) => thing,
            Err(err) => {
                eprintln!("1: {:?} {:?}", err, self.certificate_serial_number);
                return Ok(None);
            }
        };
        let res = match p.1.parse_x509() {
            Ok(thing) => thing,
            Err(err) => {
                eprintln!("2: {:?} {:?}", err, self.certificate_serial_number);
                return Ok(None);
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
                    val => panic!(format!("{:?}", val)),
                };
                rdn.append(&mut vec![Set(1, vec![Sequence(1, vec![oid, content])])]);
            }
        }
        let seq = Sequence(1, rdn);
        Ok(Some(Intermediary {
            issuer_name: base64::encode(&der_encode(&RDN { rdn: vec![seq] }).unwrap()),
            serial: base64::encode(&res.tbs_certificate.serial.to_bytes_be()),
        }))
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
    use std::collections::HashSet;
    use std::io::Write;
    use x509_parser::{RelativeDistinguishedName, X509Name};

    #[test]
    fn yhjdrfgsdf() {
        let c: CCADBReport = CCADB_URL.try_into().unwrap();
        let c: Vec<Intermediary> = c
            .report
            .into_iter()
            .map(|c| c.try_into().unwrap())
            .filter(|f: &Option<Intermediary>| f.is_some())
            .map(|f| f.unwrap())
            .collect();
        //        println!("{}", c[500].issuer_name);
        //        println!("{}", c[500].serial);
        let mut ccadb = HashSet::new();
        for i in c {
            ccadb.insert(i);
        }
        eprintln!("ccadb.len() = {:#?}", ccadb.len());
        let rev: HashSet<Intermediary> = crate::revocations_txt::Revocations::default()
            .unwrap()
            .into();
        let in_ccadb = ccadb
            .difference(&rev)
            .cloned()
            .collect::<Vec<Intermediary>>();
        let in_rev = rev
            .difference(&ccadb)
            .cloned()
            .collect::<Vec<Intermediary>>();
        eprintln!("in_ccadb = {:#?}", in_ccadb.len());
        eprintln!("in_rev = {:#?}", in_rev.len());
        eprintln!(
            "intersection = {:#?}",
            ccadb
                .intersection(&rev)
                .cloned()
                .collect::<Vec<Intermediary>>()
                .len()
        );;
        use serde::Serialize;
        #[derive(Serialize)]
        struct Dammit {
            in_ccadb: Vec<Easier>,
            in_rev: Vec<Easier>,
        };
        let d = Dammit {
            in_ccadb: in_ccadb.into_iter().map(|e| e.into()).collect(),
            in_rev: in_rev.into_iter().map(|e| e.into()).collect(),
        };
        std::fs::File::create(r#"H:\in_ccadb.json"#)
            .unwrap()
            .write_all(
                serde_json::to_string_pretty(&d.in_ccadb)
                    .unwrap()
                    .as_bytes(),
            );
        std::fs::File::create(r#"H:\in_rev.json"#)
            .unwrap()
            .write_all(serde_json::to_string_pretty(&d.in_rev).unwrap().as_bytes());
    }

    use serde::Serialize;
    #[derive(Serialize)]
    struct Easier {
        name: String,
        serial_b64: String,
        serial_hex: String,
    }

    impl From<Intermediary> for Easier {
        fn from(i: Intermediary) -> Self {
            let serial = format!(
                "{:X}",
                BigUint::from_bytes_be(&base64::decode(&i.serial).unwrap())
            );
            Easier {
                name: i.issuer_name,
                serial_b64: i.serial,
                serial_hex: serial,
            }
        }
    }
    use der_parser;
    use x509_parser::pem::pem_to_der;

    #[test]
    fn baddy() {
        let der = pem_to_der(BAD_CERT.as_bytes()).unwrap();
        match der.1.parse_x509() {
            Ok(_) => (),
            Err(e) => eprintln!("{:?}", e),
            _ => {}
        };
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

    use ::asn1_der::{FromDerObject, IntoDerObject};
    #[derive(Asn1Der)]
    struct Name {
        //        srteet: String
        rdn: RDN,
    }

    #[derive(Asn1Der)]
    struct RDN {
        RDNSequence: Vec<RelativeDistinguished>,
    }

    type RelativeDistinguished = Vec<AttributeTypeAnd>;

    #[derive(Asn1Der)]
    struct AttributeTypeAnd {
        t: AttributeType,
        v: AttributeValue,
    }

    type AttributeType = Vec<u128>;
    type AttributeValue = String;

    #[test]
    fn asdas() {
        let i: Vec<u8> =
            base64::decode("MCwxCzAJBgNVBAYTAktaMR0wGwYDVQQDExRRYXpuZXQgVHJ1c3QgTmV0d29yaw==")
                .unwrap();
        RDN::deserialize(i.iter()).unwrap();
    }

    #[test]
    fn asdfasf() {
        let ccadb: CCADBReport = CCADB_URL.parse::<Url>().unwrap().try_into().unwrap();
        for r in ccadb.report {
            println!("{}", r.certificate_issuer_organization);
        }
    }
}
