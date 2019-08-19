use serde::Deserialize;
use std::io::Read;

use crate::errors::*;
use crate::model::Intermediary;
use reqwest::Url;
use std::convert::{TryFrom, TryInto};

const CCADB_URL: &str =
    "https://ccadb-public.secure.force.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV";

struct CCADBReport {
    pub report: Vec<CCADB>,
}

impl CCADBReport {
    pub fn from_reader<R: Read>(r: R) -> Result<CCADBReport> {
        let mut report: Vec<CCADB> = vec![];
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
struct CCADB {
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

use asn1_der::*;
use base64;
use simple_asn1::ASN1Block::*;
use simple_asn1::*;
use x509_parser;

struct dammit {
    things: Vec<ASN1Block>,
}

impl ToASN1 for dammit {
    type Error = Error;

    fn to_asn1_class(&self, c: ASN1Class) -> Result<Vec<ASN1Block>> {
        Ok(self.things.clone())
    }
}

impl TryInto<Option<Intermediary>> for CCADB {
    type Error = Error;

    fn try_into(self) -> Result<Option<Intermediary>> {
        if self.pem_info.len() == 0 {
            return Ok(None);
        }
        let p = match x509_parser::pem::pem_to_der(self.pem_info.trim_matches('\'').as_bytes()) {
            Ok(thing) => thing,
            Err(err) => {
                eprintln!("{:?}", err);
                return Ok(None);
            }
        };
        let res = match p.1.parse_x509() {
            Ok(thing) => thing,
            Err(err) => {
                eprintln!("{:?}", err);
                return Ok(None);
            }
        };
        let mut answer: Vec<ASN1Block> = vec![];
//        base64::encode(&res.tbs_certificate.serial.to_bytes_be());
        for thing in res.tbs_certificate.issuer.rdn_seq {
            for attr in thing.set {
                let oid = ObjectIdentifier(
                    1,
                    OID::new(
                        attr.attr_type
                            .iter()
                            .map(|val| BigUint::from(val.clone()))
                            .collect(),
                    ),
                );
                let value = match attr.attr_value.content {
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
                let mut res = vec![Set(1, vec![Sequence(2, vec![oid, value])])];
                answer.append(&mut res);
            }
        }
        let seq = Sequence(1, answer);
        //        println!(
        //            "{}",
        //            base64::encode(&der_encode(&dammit { things: vec![seq] }).unwrap())
        //        );
        Ok(Some(Intermediary {
            issuer_name: base64::encode(&der_encode(&dammit { things: vec![seq] }).unwrap()),
            serial:  base64::encode(&res.tbs_certificate.serial.to_bytes_be()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::{get, Response};
    use x509_parser;

    #[test]
    fn yhjdrfgsdf() {
        let c: CCADBReport = CCADB_URL.try_into().unwrap();
        let t: Vec<Intermediary> = c
            .report
            .into_iter()
            .map(|c| c.try_into().unwrap())
            .filter(|f: &Option<Intermediary>| f.is_some())
            .map(|f| f.unwrap())
            .collect();
        println!("{}", t[500].issuer_name);
        println!("{}", t[500].serial);
        let mut h = HashSet::new();
        for i in t {
            h.insert(i);
        }
        eprintln!("h.len() = {:#?}", h.len());
        //        let mut resp: Response = get(CCADB_URL).unwrap();
        //        let lol = try_from(resp).unwrap();
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

    //    #[derive(Asn1Der)]
    //    struct Country {
    //        oid:
    //        country: String,
    //    }

    #[derive(Asn1Der)]
    struct Name {
        country: String,
    }

    use asn1_der::*;
    use base64;
    use simple_asn1::{der_encode, ASN1Block, ASN1Class, BigUint, ToASN1, OID};

    #[test]
    fn drfgsdf() {
        let n = Name {
            country: "EU".to_string(),
        };
        let mut serialized = vec![0u8; n.serialized_len()];
        n.serialize(serialized.iter_mut()).unwrap();

        println!("{}", base64::encode(&serialized));
    }

    struct Country {
        country: String,
    }

    use crate::errors::*;
    use simple_asn1::ASN1Block::{ObjectIdentifier, Set};
    use simple_asn1::ASN1Block::{PrintableString, Sequence};
    use std::collections::HashSet;

    impl ToASN1 for Country {
        type Error = Error;

        fn to_asn1_class(&self, c: ASN1Class) -> Result<Vec<ASN1Block>> {
            let oid = ObjectIdentifier(
                2,
                OID::new(vec![
                    BigUint::from(2 as u64),
                    BigUint::from(5 as u64),
                    BigUint::from(4 as u64),
                    BigUint::from(6 as u64),
                ]),
            );
            let name = PrintableString(self.country.len(), self.country.clone());
            let res = vec![Set(1, vec![Sequence(2, vec![oid, name])])];
            Ok(res)
        }
    }

    struct dammit {
        things: Vec<ASN1Block>,
    }

    impl ToASN1 for dammit {
        type Error = Error;

        fn to_asn1_class(&self, c: ASN1Class) -> Result<Vec<ASN1Block>> {
            Ok(self.things.clone())
        }
    }

    #[test]
    fn hdfsdf() {
        println!(
            "{:?}",
            base64::encode(
                &simple_asn1::der_encode(&Country {
                    country: "bob".to_string()
                })
                .unwrap()
            )
        );
        //        simple_asn1::der_encode(&simple_asn1::ASN1Block::PrintableString(5, "12345".to_string())).unwrap();
    }

    #[test]
    fn agdfsdf() {
        let p = x509_parser::pem::pem_to_der(EXAMPLE.as_bytes()).unwrap();
        let res = p.1.parse_x509().unwrap();
        let mut answer: Vec<ASN1Block> = vec![];
        for thing in res.tbs_certificate.issuer.rdn_seq {
            for attr in thing.set {
                let oid = ObjectIdentifier(
                    1,
                    OID::new(
                        attr.attr_type
                            .iter()
                            .map(|val| BigUint::from(val.clone()))
                            .collect(),
                    ),
                );
                let value = match attr.attr_value.content {
                    der_parser::ber::BerObjectContent::PrintableString(s) => {
                        std::str::from_utf8(s).unwrap()
                    }
                    _ => panic!("please no"),
                };
                let value = PrintableString(value.len(), value.to_string());
                let mut res = vec![Set(1, vec![Sequence(2, vec![oid, value])])];
                answer.append(&mut res);
            }
        }
        let seq = Sequence(1, answer);
        println!(
            "{}",
            base64::encode(&der_encode(&dammit { things: vec![seq] }).unwrap())
        );
    }

    #[test]
    fn thing() {
        let p = x509_parser::pem::pem_to_der(EXAMPLE.as_bytes()).unwrap();
        let res = p.1.parse_x509().unwrap();
        println!("{:?}", res.tbs_certificate.issuer.rdn_seq);
        for name in res.tbs_certificate.issuer.rdn_seq {
            for attr in name.set {
                match attr.attr_type.to_string().as_ref() {
                    "2.5.4.6" => {
                        println!("{:?}", attr.attr_value.content);
                        match attr.attr_value.content {
                            der_parser::ber::BerObjectContent::PrintableString(s) => {
                                eprintln!("String::from(s) = {:#?}", std::str::from_utf8(s))
                            }
                            _ => (),
                        }
                    }
                    _ => (),
                }
            }
        }
        //        let res = x509_parser::parse_x509_der(p.1);
        //        match res {
        //            Ok((rem, cert)) => {
        //                assert!(rem.is_empty());
        //                //
        //                assert_eq!(cert.tbs_certificate.version, 2);
        //            },
        //            _ => panic!("x509 parsing failed: {:?}", res),
        //        }
    }
}
