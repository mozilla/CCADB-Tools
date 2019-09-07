/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::{HashMap, HashSet};
use std::convert::From;

use serde::Serialize;

use crate::ccadb::CCADBReport;
use crate::firefox::cert_storage::CertStorage;
use crate::kinto::Kinto;
use crate::revocations_txt::*;
use std::hash::Hash;
use std::iter::Sum;

use crate::errors::*;

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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_ccadb_not_in_cert_storage: Option<Vec<Intermediary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_cert_storage_not_in_ccadb: Option<Vec<Intermediary>>,
}

type WithRevocations = (CertStorage, Kinto, Revocations);
type WithoutRevocations = (CertStorage, Kinto);
type CCADBDiffCertStorage = (CertStorage, CCADBReport);

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
            in_cert_storage_not_in_ccadb: None,
            in_ccadb_not_in_cert_storage: None,
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
            in_cert_storage_not_in_ccadb: None,
            in_ccadb_not_in_cert_storage: None,
        }
    }
}

impl From<CCADBDiffCertStorage> for Return {
    fn from(values: CCADBDiffCertStorage) -> Self {
        let cert_storage: HashSet<Intermediary> = values.0.into();
        let ccadb: HashSet<Intermediary> = values.1.into();
        Return {
            in_kinto_not_in_cert_storage: None,
            in_cert_storage_not_in_kinto: None,
            in_cert_storage_not_in_revocations: None,
            in_revocations_not_in_cert_storage: None,
            in_revocations_not_in_kinto: None,
            in_kinto_not_in_revocations: None,
            in_ccadb_not_in_cert_storage: Some(
                ccadb
                    .difference(&cert_storage)
                    .cloned()
                    .collect::<Vec<Intermediary>>(),
            ),
            in_cert_storage_not_in_ccadb: Some(
                cert_storage
                    .difference(&ccadb)
                    .cloned()
                    .collect::<Vec<Intermediary>>(),
            ),
        }
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

//struct Summary {
//    pub summary: HashSet<Intermediary>,
//    pub origin: &'static str
//}
//
//impl <T: Named + Into<HashSet<Intermediary>>> From<T> for Summary {
//    fn from(value: T) -> Self {
//        let name = value.serde_name();
//        Summary{ summary: value.into() , origin: name }
//    }
//}
//
//
//macro_rules! serialize {
//     ( $( $x:expr ),* ) => {
//        {
//            let mut temp_vec: Vec<S> = Vec::new();
//            $(
//                temp_vec.push($x);
//            )*
//            temp_vec
//        }
//    };
//}
//
//macro_rules! tst {
//    ($($n:ident),*) => {
//        let mut i = 0;
//        $(
//            tst!(i, $n);
//            i += 1;
//        )*
//    };
//
//    ($idx:expr, $($n:ident),*) => {
//        $(
//            println!("{} {}", $idx, $n);
//        )*
//    };
//
//    ($idx:expr, $lol:ident, $($n:ident),*) => {
//        let mut j = 0;
//        $(
//            println!("{}", $n);
//        )*
//    }
//}
//
//#[cfg(test)]
//mod deasda {
//    use super::*;
//
//    #[test]
//    fn afasds() {
//        let a = 1;
//        let b= 2;
//        let c = 3;
////        tst!(a,b,c);
//    }
//}
//
//
//pub fn serialize_differences<T>(values: Vec<T>) -> Result<String>
//where
//    T: Named + Into<HashSet<Intermediary>> {
//    let values: Vec<Summary> = values.into_iter().map(|e| Summary::from(e)).collect();
//    let mut ret: HashMap<String, Vec<Intermediary>> = HashMap::new();
//    for i in 0..values.len() {
//        for j in 0..values.len() {
//            if i == j {
//                continue;
//            }
//            let left;
//            let right;
//            unsafe {
//                left = values.get_unchecked(i);
//                right = values.get_unchecked(j);
//            }
//            ret.insert(
//                format!("in_{}_not_in_{}", left.origin, right.origin),
//                left.summary.difference(&right.summary).cloned().collect()
//            );
//            ret.insert(
//                format!("in_{}_not_in_{}", right.origin, left.origin),
//                right.summary.difference(&left.summary).cloned().collect()
//            );
//        }
//    }
//    serde_json::to_string_pretty(&ret).chain_err(|| "failed to serialize differences")
//}
//
//pub trait Named {
//    fn serde_name(&self) -> &'static str;
//}
