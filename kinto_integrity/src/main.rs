#![feature(slice_patterns)]
#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate rocket;

use errors::*;

mod firefox;
mod kinto;
mod model;
mod revocations_txt;

use kinto::*;
use model::*;
use revocations_txt::*;

use crate::firefox::Firefox;
use reqwest::Url;
use std::collections::HashSet;
use std::convert::TryInto;
use rocket::http::RawStr;

const USER_AGENT: &str = "github.com/mozilla/CCADB-Tools/kintoDiffCCADB chris@chenderson.org";
const X_AUTOMATED_TOOL: &str = "github.com/mozilla/CCADB-Tools/kintoDiffCCADB";

mod errors {
    use std::convert::From;

    error_chain! {
        foreign_links {
            Fmt(::std::fmt::Error);
            Io(::std::io::Error);
            Reqwest(reqwest::Error);
            Infallible(std::convert::Infallible);
        }
    }

    impl std::convert::From<rkv::StoreError> for Error {
        fn from(err: rkv::StoreError) -> Self {
            format!("{:?}", err).into()
        }
    }
}

#[get("/")]
fn default() -> Result<String> {
    let revocations: Revocations = Revocations::default()?;
    let revocations: HashSet<Intermediary> = revocations.into();
    let kinto: Kinto = Kinto::default()?;
    let kinto: HashSet<Intermediary> = kinto.into();
    let cert_storage = Firefox::default()?;
    let cert_storage: HashSet<Intermediary> = cert_storage.into();
    Ok(format!(
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
    ))
}

#[get("/with_revocations?<url>")]
fn with_revocations(url: &RawStr) -> Result<String> {
    let revocations: Revocations = match url.as_str().parse::<Url>() {
        Ok(url) => url.try_into()?,
        Err(err) => Err(format!("{:?}", err))?,
    };
    let revocations: HashSet<Intermediary> = revocations.into();
    let kinto: Kinto = Kinto::default()?;
    let kinto: HashSet<Intermediary> = kinto.into();
    let cert_storage = Firefox::default()?;
    let cert_storage: HashSet<Intermediary> = cert_storage.into();
    Ok(format!(
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
    ))
}

#[get("/without_revocations")]
fn without_revocations() -> Result<String> {
    let kinto: Kinto = Kinto::default()?;
    let kinto: HashSet<Intermediary> = kinto.into();
    let cert_storage = Firefox::default()?;
    let cert_storage: HashSet<Intermediary> = cert_storage.into();
    Ok(format!(
        r#"
kinto.len() = {:#?}
cert_storage.len() = {:#?}
kinto.symmetric_difference(&certstorage) = {:#?}"#,
        kinto.len(),
        cert_storage.len(),
        kinto.symmetric_difference(&cert_storage)
    ))
}

fn main() -> Result<()> {
    firefox::init();
    rocket::ignite()
        .mount("/", routes![default, with_revocations])
        .launch();
    Ok(())
}
