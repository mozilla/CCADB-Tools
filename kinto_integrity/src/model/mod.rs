/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::HashSet;
use std::convert::From;

use serde::Serialize;

use crate::ccadb::{CCADBReport, OneCRLStatus};
use crate::firefox::cert_storage::CertStorage;
use crate::kinto::Kinto;
use crate::revocations_txt::*;

//1. In Kinto but not in cert_storage
//2. In cert_storage but not in Kinto
//3. In cert_storage but not in revocations.txt
//4. In revocations.txt but not in cert_storage
//5. in revocations.txt but not in Kinto.
//6. In Kinto but not in revocations.txt

#[derive(Serialize)]
pub struct Return {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_kinto_not_in_cert_storage: Option<Vec<Intermediary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_cert_storage_not_in_kinto: Option<Vec<Intermediary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_cert_storage_not_in_revocations: Option<Vec<Intermediary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_revocations_not_in_cert_storage: Option<Vec<Intermediary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_revocations_not_in_kinto: Option<Vec<Intermediary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_kinto_not_in_revocations: Option<Vec<Intermediary>>,
}

type WithRevocations = (CertStorage, Kinto, Revocations);
type WithoutRevocations = (CertStorage, Kinto);

impl From<WithRevocations> for Return {
    fn from(values: WithRevocations) -> Self {
        let cert_storage: HashSet<Intermediary> = values.0.into();
        let kinto: HashSet<Intermediary> = values.1.into();
        let revocations: HashSet<Intermediary> = values.2.into();
        Return {
            in_kinto_not_in_cert_storage: Some(
                kinto
                    .difference(&cert_storage)
                    .cloned()
                    .collect::<Vec<Intermediary>>(),
            ),
            in_cert_storage_not_in_kinto: Some(
                cert_storage
                    .difference(&kinto)
                    .cloned()
                    .collect::<Vec<Intermediary>>(),
            ),
            in_cert_storage_not_in_revocations: Some(
                cert_storage
                    .difference(&revocations)
                    .cloned()
                    .collect::<Vec<Intermediary>>(),
            ),
            in_revocations_not_in_cert_storage: Some(
                revocations
                    .difference(&cert_storage)
                    .cloned()
                    .collect::<Vec<Intermediary>>(),
            ),
            in_revocations_not_in_kinto: Some(
                revocations
                    .difference(&kinto)
                    .cloned()
                    .collect::<Vec<Intermediary>>(),
            ),
            in_kinto_not_in_revocations: Some(
                kinto
                    .difference(&revocations)
                    .cloned()
                    .collect::<Vec<Intermediary>>(),
            ),
        }
    }
}

impl From<WithoutRevocations> for Return {
    fn from(values: WithoutRevocations) -> Self {
        let cert_storage: HashSet<Intermediary> = values.0.into();
        let kinto: HashSet<Intermediary> = values.1.into();
        Return {
            in_kinto_not_in_cert_storage: Some(
                kinto
                    .difference(&cert_storage)
                    .cloned()
                    .collect::<Vec<Intermediary>>(),
            ),
            in_cert_storage_not_in_kinto: Some(
                cert_storage
                    .difference(&kinto)
                    .cloned()
                    .collect::<Vec<Intermediary>>(),
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
    pub added_and_present_in_cert_storage: Vec<Intermediary>,
    pub expired_and_present_in_cert_storage: Vec<Intermediary>,
    pub ready_to_add_and_present_in_cert_storage: Vec<Intermediary>,
    pub absent_from_ccadb_and_present_in_cert_storage: Vec<Intermediary>,
    pub added_and_absent_from_cert_storage: Vec<Intermediary>,
    pub expired_and_absent_from_cert_storage: Vec<Intermediary>,
    pub ready_to_add_and_absent_from_cert_storage: Vec<Intermediary>,
    pub absent_from_ccadb_and_absent_from_cert_storage: Vec<Intermediary>,
    pub no_revocation_status_and_in_cert_storage: Vec<Intermediary>,
    pub no_revocation_status_and_absent_from_cert_storage: Vec<Intermediary>,
}

impl From<(CertStorage, CCADBReport)> for CCADBDiffCertStorage {
    fn from(values: (CertStorage, CCADBReport)) -> Self {
        let mut added: HashSet<Intermediary> = HashSet::new();
        let mut expired: HashSet<Intermediary> = HashSet::new();
        let mut ready: HashSet<Intermediary> = HashSet::new();
        let mut no_status: HashSet<Intermediary> = HashSet::new();
        let mut union: HashSet<Intermediary> = HashSet::new();
        values
            .1
            .report
            .into_iter()
            // Convert the entry into an intermediate but keep around its OneCRL Status
            .map(|entry| (entry.one_crl_status.clone(), entry.into()))
            // Filter out any that failed to parse, these must be logged.
            .filter(|e: &(String, Option<Intermediary>)| e.1.is_some())
            .map(|e: (String, Option<Intermediary>)| (e.0, e.1.unwrap()))
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
        let cert_storage: HashSet<Intermediary> = values.0.into();
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

#[derive(Eq, PartialEq, Hash, Debug, Serialize, Clone)]
pub struct Intermediary {
    pub issuer_name: String,
    pub serial: String,
}

impl From<Revocations> for HashSet<Intermediary> {
    /// Flattens out:
    ///     issuer
    ///      serial
    ///      serial
    ///      serial
    /// To:
    ///     [(issuer, serial), (issuer, serial), (issuer, serial)]
    fn from(revocations: Revocations) -> Self {
        let mut set: HashSet<Intermediary> = HashSet::new();
        for issuer in revocations.data.into_iter() {
            for serial in issuer.serials.into_iter() {
                set.insert(Intermediary {
                    issuer_name: issuer.issuer_name.clone(),
                    serial: serial,
                });
            }
        }
        set
    }
}

impl From<Kinto> for HashSet<Intermediary> {
    /// The interesting thing to point out here is that Kinto has
    /// many duplicate issuer/serial pairs for which I am not keen
    /// as to the purpose. They have different "id"s, which I reckon
    /// are Kinto specific IDs, however I am implicitly deduplicating
    /// Kinto in this regard by shoving everything into a set.
    ///
    /// Please see kinto:tests::find_duplicates
    fn from(kinto: Kinto) -> Self {
        let mut set: HashSet<Intermediary> = HashSet::new();
        for entry in kinto.data.into_iter() {
            set.insert(Intermediary {
                issuer_name: entry.issuer_name,
                serial: entry.serial_number,
            });
        }
        set
    }
}

impl From<CertStorage> for HashSet<Intermediary> {
    fn from(cs: CertStorage) -> Self {
        cs.data
            .into_iter()
            .map(|is| Intermediary {
                issuer_name: is.issuer_name,
                serial: is.serial,
            })
            .collect()
    }
}

impl From<CCADBReport> for HashSet<Intermediary> {
    fn from(report: CCADBReport) -> Self {
        report
            .report
            .into_iter()
            .map(|entry| entry.into())
            .filter(|entry: &Option<Intermediary>| entry.is_some())
            .map(|entry| entry.unwrap())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::*;
    use reqwest::Url;
    use std::convert::TryInto;

    use crate::kinto::tests::*;
    use crate::revocations_txt::tests::*;

    #[test]
    fn smoke_from_revocations() -> Result<()> {
        let rev: Revocations = REVOCATIONS_TXT
            .parse::<Url>()
            .chain_err(|| "bad URL")?
            .try_into()?;
        let int: HashSet<Intermediary> = rev.into();
        eprintln!("int = {:#?}", int);
        Ok(())
    }

    #[test]
    fn smoke_from_kinto() -> Result<()> {
        let kinto: Kinto = KINTO.parse::<Url>().chain_err(|| "bad URL")?.try_into()?;
        let int: HashSet<Intermediary> = kinto.into();
        eprintln!("int = {:#?}", int);
        Ok(())
    }
}
