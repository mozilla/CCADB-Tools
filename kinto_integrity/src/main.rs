#![feature(slice_patterns)]
#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate rocket;

use url::form_urlencoded::parse as url_decode;

use errors::*;

mod firefox;
pub mod http;
mod kinto;
mod model;
mod revocations_txt;

use kinto::*;
use model::*;
use revocations_txt::*;

use crate::firefox::Firefox;
use reqwest::Url;
use rocket::http::RawStr;
use std::convert::TryInto;

mod errors {
    use std::convert::From;

    error_chain! {
        foreign_links {
            Fmt(::std::fmt::Error);
            Io(::std::io::Error);
            Reqwest(reqwest::Error);
            Infallible(std::convert::Infallible);
            Json(serde_json::error::Error);
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
    let kinto: Kinto = Kinto::default()?;
    let cert_storage = Firefox::default()?;
    let result: Return = (cert_storage, kinto, revocations).into();
    Ok(serde_json::to_string(&result)?)
}

#[get("/with_revocations?<url>")]
fn with_revocations(url: &RawStr) -> Result<String> {
    // https://docs.rs/url/2.1.0/url/form_urlencoded/fn.parse.html expects that you are going
    // to give it a bunch of key,value pairs such as a=b&c=d&e=f ... however we are only giving it
    // the right-hand side of url=<revocations_url> which makes it think that <revocations_url>
    // is actually the key and not the pair, hence why in the mapper function we take pair.0
    // and throw away pair.1 which is just the empty string.
    let revocations_url: String = url_decode(url.as_bytes())
        .into_owned()
        .into_iter()
        .map(|pair| format!("{}", pair.0))
        .collect::<Vec<String>>()
        .join("");
    let revocations: Revocations = match revocations_url.as_str().parse::<Url>() {
        Ok(url) => url.try_into()?,
        Err(err) => Err(format!("{:?}", err))?,
    };
    let kinto: Kinto = Kinto::default()?;
    let cert_storage = Firefox::default()?;
    let result: Return = (cert_storage, kinto, revocations).into();
    Ok(serde_json::to_string(&result)?)
}

#[post("/with_revocations", format = "text/plain", data = "<revocations_txt>")]
fn post_revocations(revocations_txt: String) -> Result<String> {
    let revocations = revocations_txt.to_string().try_into()?;
    let kinto: Kinto = Kinto::default()?;
    let cert_storage = Firefox::default()?;
    let result: Return = (cert_storage, kinto, revocations).into();
    Ok(serde_json::to_string(&result)?)
}

#[get("/without_revocations")]
fn without_revocations() -> Result<String> {
    let kinto: Kinto = Kinto::default()?;
    let cert_storage = Firefox::default()?;
    let result: Return = (cert_storage, kinto).into();
    Ok(serde_json::to_string(&result)?)
}

fn main() -> Result<()> {
    firefox::init();
    rocket::ignite()
        .mount("/", routes![default, with_revocations, without_revocations])
        .launch();
    Ok(())
}
