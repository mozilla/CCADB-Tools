/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::HashSet;
use std::convert::From;

use serde::Serialize;

use crate::ccadb::{CCADB, OneCRLStatus};
use crate::firefox::cert_storage::CertStorage;
use crate::kinto::Kinto;
use crate::revocations_txt::*;
use std::hash::{Hash, Hasher};

//1. In Kinto but not in cert_storage
//2. In cert_storage but not in Kinto
//3. In cert_storage but not in revocations.txt
//4. In revocations.txt but not in cert_storage
//5. in revocations.txt but not in Kinto.
//6. In Kinto but not in revocations.txt

#[derive(Serialize)]
pub struct Return {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_kinto_not_in_cert_storage: Option<Vec<Revocation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_cert_storage_not_in_kinto: Option<Vec<Revocation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_cert_storage_not_in_revocations: Option<Vec<Revocation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_revocations_not_in_cert_storage: Option<Vec<Revocation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_revocations_not_in_kinto: Option<Vec<Revocation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_kinto_not_in_revocations: Option<Vec<Revocation>>,
}

type WithRevocations = (CertStorage, Kinto, Revocations);
type WithoutRevocations = (CertStorage, Kinto);

impl From<WithRevocations> for Return {
    fn from(values: WithRevocations) -> Self {
        let cert_storage: HashSet<Revocation> = values.0.into();
        let kinto: HashSet<Revocation> = values.1.into();
        let revocations: HashSet<Revocation> = values.2.into();
        Return {
            in_kinto_not_in_cert_storage: Some(
                kinto
                    .difference(&cert_storage)
                    .cloned()
                    .collect::<Vec<Revocation>>(),
            ),
            in_cert_storage_not_in_kinto: Some(
                cert_storage
                    .difference(&kinto)
                    .cloned()
                    .collect::<Vec<Revocation>>(),
            ),
            in_cert_storage_not_in_revocations: Some(
                cert_storage
                    .difference(&revocations)
                    .cloned()
                    .collect::<Vec<Revocation>>(),
            ),
            in_revocations_not_in_cert_storage: Some(
                revocations
                    .difference(&cert_storage)
                    .cloned()
                    .collect::<Vec<Revocation>>(),
            ),
            in_revocations_not_in_kinto: Some(
                revocations
                    .difference(&kinto)
                    .cloned()
                    .collect::<Vec<Revocation>>(),
            ),
            in_kinto_not_in_revocations: Some(
                kinto
                    .difference(&revocations)
                    .cloned()
                    .collect::<Vec<Revocation>>(),
            ),
        }
    }
}

impl From<WithoutRevocations> for Return {
    fn from(values: WithoutRevocations) -> Self {
        let cert_storage: HashSet<Revocation> = values.0.into();
        let kinto: HashSet<Revocation> = values.1.into();
        Return {
            in_kinto_not_in_cert_storage: Some(
                kinto
                    .difference(&cert_storage)
                    .cloned()
                    .collect::<Vec<Revocation>>(),
            ),
            in_cert_storage_not_in_kinto: Some(
                cert_storage
                    .difference(&kinto)
                    .cloned()
                    .collect::<Vec<Revocation>>(),
            ),
            in_cert_storage_not_in_revocations: None,
            in_revocations_not_in_cert_storage: None,
            in_revocations_not_in_kinto: None,
            in_kinto_not_in_revocations: None,
        }
    }
}

#[derive(Serialize)]
pub struct CCADBDiffCertStorage {
    pub added_and_present_in_cert_storage: Vec<Revocation>,
    pub expired_and_present_in_cert_storage: Vec<Revocation>,
    pub ready_to_add_and_present_in_cert_storage: Vec<Revocation>,
    pub absent_from_ccadb_and_present_in_cert_storage: Vec<Revocation>,
    pub added_and_absent_from_cert_storage: Vec<Revocation>,
    pub expired_and_absent_from_cert_storage: Vec<Revocation>,
    pub ready_to_add_and_absent_from_cert_storage: Vec<Revocation>,
    pub absent_from_ccadb_and_absent_from_cert_storage: Vec<Revocation>,
    pub no_revocation_status_and_in_cert_storage: Vec<Revocation>,
    pub no_revocation_status_and_absent_from_cert_storage: Vec<Revocation>,
}

impl From<(CertStorage, CCADB)> for CCADBDiffCertStorage {
    fn from(values: (CertStorage, CCADB)) -> Self {
        let mut added: HashSet<Revocation> = HashSet::new();
        let mut expired: HashSet<Revocation> = HashSet::new();
        let mut ready: HashSet<Revocation> = HashSet::new();
        let mut no_status: HashSet<Revocation> = HashSet::new();
        let mut union: HashSet<Revocation> = HashSet::new();
        values
            .1
            .report
            .into_iter()
            // Convert the entry into an intermediate but keep around its OneCRL Status
            .map(|entry| (entry.one_crl_status.clone(), entry.into()))
            // Filter out any that failed to parse, these must be logged.
            .filter(|e: &(String, Option<Revocation>)| e.1.is_some())
            .map(|e: (String, Option<Revocation>)| (e.0, e.1.unwrap()))
            // For each one, put their clone into the union of all entries and then
            // put the original into its appropriate bucket.
            .for_each(|entry| {
                union.insert(entry.1.clone());
                match OneCRLStatus::from(entry.0.as_str()) {
                    OneCRLStatus::Empty => {
                        no_status.insert(entry.1);
                    }
                    OneCRLStatus::Ready => {
                        ready.insert(entry.1);
                    }
                    OneCRLStatus::Added => {
                        added.insert(entry.1);
                    }
                    OneCRLStatus::Expired => {
                        expired.insert(entry.1);
                    }
                    OneCRLStatus::Unknown => {
                        error!(r#"received the unknown OneCRL status "{}""#, entry.0)
                    }
                }
            });
        let mut cert_storage: HashSet<Revocation> = values.0.into();
        for ccadb_entry in union.iter() {
            if let Some(mut storage_entry) = cert_storage.take(ccadb_entry) {
                storage_entry.set_sha_256(ccadb_entry);
                cert_storage.insert(storage_entry);
            }
        }
        return CCADBDiffCertStorage {
            added_and_present_in_cert_storage: added.intersection(&cert_storage).cloned().collect(),
            expired_and_present_in_cert_storage: expired
                .intersection(&cert_storage)
                .cloned()
                .collect(),
            ready_to_add_and_present_in_cert_storage: ready
                .intersection(&cert_storage)
                .cloned()
                .collect(),
            absent_from_ccadb_and_present_in_cert_storage: cert_storage
                .difference(&union)
                .cloned()
                .collect(),
            added_and_absent_from_cert_storage: added.difference(&cert_storage).cloned().collect(),
            expired_and_absent_from_cert_storage: expired
                .difference(&cert_storage)
                .cloned()
                .collect(),
            ready_to_add_and_absent_from_cert_storage: ready
                .difference(&cert_storage)
                .cloned()
                .collect(),
            absent_from_ccadb_and_absent_from_cert_storage: vec![],
            no_revocation_status_and_in_cert_storage: no_status
                .intersection(&cert_storage)
                .cloned()
                .collect(),
            no_revocation_status_and_absent_from_cert_storage: no_status
                .difference(&cert_storage)
                .cloned()
                .collect(),
        };
    }
}

#[derive(Eq, Debug, Serialize, Clone)]
#[serde(untagged)]
pub enum Revocation {
    IssuerSerial {
        issuer: String,
        serial: String,
        sha_256: Option<String>,
    },
    SubjectKeyHash {
        subject: String,
        key_hash: String,
        sha_256: Option<String>,
    }
}

impl Hash for Revocation {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Revocation::IssuerSerial {issuer, serial, sha_256: _} => {
                state.write(issuer.as_bytes());
                state.write(serial.as_bytes());
            }
            Revocation::SubjectKeyHash {subject, key_hash, sha_256: _} => {
                state.write(subject.as_bytes());
                state.write(key_hash.as_bytes());
            }
        }
    }
}

impl PartialEq for Revocation {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Revocation::SubjectKeyHash{subject: _, key_hash: _, sha_256: _ }, Revocation::IssuerSerial{issuer: _, serial: _, sha_256: _ }) => false,
            (Revocation::IssuerSerial{issuer: _, serial: _, sha_256: _ }, Revocation::SubjectKeyHash{subject: _, key_hash: _, sha_256: _ }) => false,
            (Revocation::SubjectKeyHash{subject: cs, key_hash: ch, sha_256: _ }, Revocation::SubjectKeyHash{subject: rs, key_hash: rh, sha_256: _ }) => cs == rs && ch == rh,
            (Revocation::IssuerSerial{issuer: ci, serial: cs, sha_256: _ }, Revocation::IssuerSerial{issuer: ri, serial: rs, sha_256: _ }) => ci == ri && cs == rs,
        }
    }
}

impl Revocation {
    pub fn new_issuer_serial(mut issuer: String, mut serial: String, sha_256: Option<String>) -> Revocation {
        issuer = crate::x509::b64_to_rdn(issuer.into_bytes()).unwrap();
        serial = match base64::decode(serial.as_bytes()) {
            Ok(s) => Revocation::btoh(&s),
            Err(_) => serial,
        };
        Revocation::IssuerSerial {
            issuer,
            serial,
            sha_256,
        }
    }

    pub fn new_subject_key_hash(mut subject: String, key_hash: String, sha_256: Option<String>) -> Revocation {
        subject = crate::x509::b64_to_rdn(subject.into_bytes()).unwrap();
        Revocation::SubjectKeyHash {
            subject,
            key_hash,
            sha_256,
        }
    }

    pub fn set_sha_256(&mut self, other: &Self) {
        match (self, other) {
            (Revocation::IssuerSerial {issuer:_, serial: _, sha_256: l} ,Revocation::IssuerSerial {issuer:_, serial: _, sha_256: Some(val)}) => {
                l.replace(val.clone());
            },
            (Revocation::IssuerSerial {issuer:_, serial: _, sha_256: l} ,Revocation::IssuerSerial {issuer:_, serial: _, sha_256: None}) => {
                std::mem::replace(l, None);
            },
            (Revocation::SubjectKeyHash {subject: _, key_hash: _, sha_256: l}, Revocation::SubjectKeyHash {subject: _, key_hash: _, sha_256: Some(val)}) => {
                l.replace(val.clone());
            },
            (Revocation::SubjectKeyHash {subject: _, key_hash: _, sha_256: l}, Revocation::SubjectKeyHash {subject: _, key_hash: _, sha_256: None}) => {
                std::mem::replace(l, None);
            }
            _ => {}
        };
    }

    pub fn btoh(input: &[u8]) -> String {
        let mut hex = String::new();
        let mut i = 1;
        for byte in input {
            hex.push_str(&format!("{:02X}", byte));
            if i != input.len() {
                hex.push(':');
            }
            i += 1;
        }
        hex
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::*;
    use reqwest::Url;
    use std::convert::TryInto;

    use crate::kinto::tests::*;


    #[test]
    fn smoke_from_revocations() -> Result<()> {
        let rev: Revocations = REVOCATIONS_TXT
            .parse::<Url>()
            .chain_err(|| "bad URL")?
            .try_into()?;
        let int: HashSet<crate::model::Revocation> = rev.into();
        eprintln!("int = {:#?}", int);
        Ok(())
    }

    #[test]
    fn smoke_from_kinto() -> Result<()> {
        let kinto: Kinto = KINTO.parse::<Url>().chain_err(|| "bad URL")?.try_into()?;
        let int: HashSet<crate::model::Revocation> = kinto.into();
        eprintln!("int = {:#?}", int);
        Ok(())
    }
}
