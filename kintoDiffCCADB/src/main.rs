#![feature(slice_patterns)]
#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;

mod cert_storage;
mod firefox;
mod intermediary;
mod kinto;
mod revocations_txt;
mod updater;

use cert_storage::*;
use errors::*;
use intermediary::*;
use kinto::*;
use revocations_txt::*;

use crate::firefox::Firefox;
use reqwest::Url;
use std::collections::HashSet;
use std::convert::TryInto;
use std::path::Path;

const USER_AGENT: &str = "github.com/mozilla/CCADB-Tools/kinto_integrity chris@chenderson.org";
const X_AUTOMATED_TOOL: &str = "github.com/mozilla/CCADB-Tools/kinto_integrity";

mod errors {
    use std::convert::From;
    error_chain! {}

    impl From<reqwest::Error> for Error {
        fn from(err: reqwest::Error) -> Self {
            format!("{:?}", err).into()
        }
    }

    impl From<std::io::Error> for Error {
        fn from(err: std::io::Error) -> Self {
            format!("{:?}", err).into()
        }
    }

    impl From<std::convert::Infallible> for Error {
        fn from(err: std::convert::Infallible) -> Self {
            format!("{:?}", err).into()
        }
    }

    impl std::convert::From<rkv::StoreError> for Error {
        fn from(err: rkv::StoreError) -> Self {
            format!("{:?}", err).into()
        }
    }
}

fn doit() -> String {
    let revocations: Revocations =
        "https://bug1553256.bmoattachments.org/attachment.cgi?id=9066502"
            .parse::<Url>()
            .unwrap()
            .try_into()
            .unwrap();
    let kinto: Kinto =
        "https://settings.prod.mozaws.net/v1/buckets/security-state/collections/onecrl/records"
            .parse::<Url>()
            .unwrap()
            .try_into()
            .unwrap();
    let revocations: HashSet<Intermediary> = revocations.into();
    let kinto: HashSet<Intermediary> = kinto.into();
    let profile: firefox::profile::Profile = (*firefox::FIREFOX)
        .lock()
        .unwrap()
        .create_profile()
        .unwrap();
    let cert_storage: CertStorage = Path::new(&profile.home).to_path_buf().try_into().unwrap();
    let cert_storage: HashSet<Intermediary> = cert_storage.into();
    format!(
        r#"
revocations.len() = {:#?}
kinto.len() = {:#?}
cert_storage.len() = {:#?}
revocations.symmetric_difference(&kinto) = {:#?}
revocations.symmetric_difference(&certstorage) = {:#?}"#,
        revocations.len(),
        kinto.len(),
        cert_storage.len(),
        revocations.symmetric_difference(&kinto),
        revocations.symmetric_difference(&cert_storage)
    )
}

#[macro_use] extern crate rocket;

#[get("/")]
fn integrity() -> String {
    doit()
}

fn main() {
    rocket::ignite().mount("/", routes![integrity]).launch();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        println!("{}", doit());
    }
}
