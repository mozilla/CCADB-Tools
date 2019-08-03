#![feature(slice_patterns)]
#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate rocket;

use errors::*;

mod cert_storage;
mod firefox;
mod intermediary;
mod kinto;
mod revocations_txt;

use cert_storage::*;
use intermediary::*;
use kinto::*;
use revocations_txt::*;

use reqwest::Url;
use std::collections::HashSet;
use std::convert::TryInto;
use std::path::Path;
use std::time::Duration;

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

fn doit() -> Result<String> {
    let revocations: Revocations =
        "https://bug1553256.bmoattachments.org/attachment.cgi?id=9066502"
            .parse::<Url>()
            .chain_err(|| "failed to download revocations.txt")?
            .try_into()
            .chain_err(|| "failed to parse revocations.txt")?;
    let kinto: Kinto =
        "https://settings.prod.mozaws.net/v1/buckets/security-state/collections/onecrl/records"
            .parse::<Url>()
            .chain_err(|| "failed to download OneCRL")?
            .try_into()
            .chain_err(|| "failed to parse OneCRL")?;
    let revocations: HashSet<Intermediary> = revocations.into();
    let kinto: HashSet<Intermediary> = kinto.into();
    let profile = match (*firefox::FIREFOX).lock() {
        Err(err) => Err(format!("{:?}", err))?,
        Ok(mut ff) => ff
            .update()
            .chain_err(|| "failed to update Firefox Nightly")?
            .create_profile()
            .chain_err(|| "failed to create a profile for Firefox Nightly")?,
    };
    let cert_storage: CertStorage = Path::new(&profile.home)
        .to_path_buf()
        .try_into()
        .chain_err(|| "failed to parse cert_storage")?;
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



#[get("/")]
fn integrity() -> Result<String> {
    doit()
}

fn main() -> Result<()> {
    firefox::init();
    rocket::ignite().mount("/", routes![integrity]).launch();
    Ok(())
}
