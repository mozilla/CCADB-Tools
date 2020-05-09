/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![feature(proc_macro_hygiene, decl_macro)]

extern crate proc_macro;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate rocket;

#[macro_use]
mod errors;

use reqwest::Url;
use rocket::http::RawStr;
use rocket::Data;
use std::convert::TryInto;

// A fairly hefty import for only one function. If you find something lighter weight
// but just as well liked then please do replace this.
use url::form_urlencoded::parse as url_decode;

mod ccadb;
mod firefox;
mod http;
mod kinto;
mod model;
mod revocations_txt;
mod nginx;
mod configuration;

use crate::ccadb::CCADB;
use errors::*;
use firefox::*;
use kinto::*;
use model::*;
use revocations_txt::*;

mod nightly {

    use super::*;

    #[get("/default")]
    pub fn default() -> IntegrityResult<String> {
        let revocations: Revocations = Revocations::default()?;
        let kinto: Kinto = Kinto::default()?;
        let cert_storage = FIREFOX_NIGHTLY.cert_storage()?;
        let result: Return = (cert_storage, kinto, revocations).into();
        Ok(serde_json::to_string_pretty(&result)?)
    }

    #[get("/with_revocations?<url>")]
    pub fn with_revocations(url: &RawStr) -> IntegrityResult<String> {
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
            Err(err) => Err(err.to_string())?,
        };
        let kinto: Kinto = Kinto::default()?;
        let cert_storage = FIREFOX_NIGHTLY.cert_storage()?;
        let result: Return = (cert_storage, kinto, revocations).into();
        Ok(serde_json::to_string_pretty(&result)?)
    }

    #[post("/with_revocations", format = "text/plain", data = "<revocations_txt>")]
    pub fn post_revocations(revocations_txt: Data) -> IntegrityResult<String> {
        let revocations: Revocations = revocations_txt.open().try_into()?;
        let kinto: Kinto = Kinto::default()?;
        let cert_storage = FIREFOX_NIGHTLY.cert_storage()?;
        let result: Return = (cert_storage, kinto, revocations).into();
        Ok(serde_json::to_string_pretty(&result)?)
    }

    #[get("/without_revocations")]
    pub fn without_revocations() -> IntegrityResult<String> {
        let kinto: Kinto = Kinto::default()?;
        let cert_storage = FIREFOX_NIGHTLY.cert_storage()?;
        let result: Return = (cert_storage, kinto).into();
        Ok(serde_json::to_string_pretty(&result)?)
    }

    #[get("/ccadb_cert_storage")]
    pub fn ccadb_cert_storage() -> IntegrityResult<String> {
        let ccadb: CCADB = CCADB::default()?;
        let cert_storage = FIREFOX_NIGHTLY.cert_storage()?;
        let result: CCADBDiffCertStorage = (cert_storage, ccadb).into();
        Ok(serde_json::to_string_pretty(&result)?)
    }

    #[patch("/update_cert_storage")]
    pub fn update_cert_storage() -> IntegrityResult<()> {
        Ok(FIREFOX_NIGHTLY.update_cert_storage()?)
    }

    #[patch("/update_firefox")]
    pub fn update_firefox() -> IntegrityResult<()> {
        Ok(FIREFOX_NIGHTLY.force_update()?)
    }
}

#[macro_use]
extern crate log;

fn init_logging() {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Off)
        .level_for("kinto_integrity", log::LevelFilter::Debug)
        .level_for("rocket", log::LevelFilter::Debug)
        .level_for("_", log::LevelFilter::Debug)
        .level_for("hyper", log::LevelFilter::Error)
        .level_for("tokio", log::LevelFilter::Error)
        .level_for("tokio_reactor", log::LevelFilter::Error)
        .chain(std::io::stdout())
        .apply()
        .unwrap();
}

pub fn get_port() -> IntegrityResult<u16> {
    Ok(match std::env::var("PORT") {
        Ok(port) => port.parse().unwrap(),
        Err(_) => 8080,
    } as u16)
}

fn main() -> IntegrityResult<()> {
    init_logging();
    firefox::init();
    let port = get_port()?;
    nginx::NginxBuilder::new().port(port).redirect(8080).
        location("default").
        location("with_revocations").
        location("without_revocations").
        location("ccadb_cert_storage").
        location("update_cert_storage").
        location("update_firefox").
        build()?.
        start()?;
    let config = rocket::Config::build(rocket::config::Environment::Production)
        .port(8080)
        .finalize()
        .unwrap();
    rocket::custom(config)
        .mount(
            "/",
            routes![
                nightly::default,
                nightly::with_revocations,
                nightly::post_revocations,
                nightly::without_revocations,
                nightly::ccadb_cert_storage,
                nightly::update_cert_storage,
                nightly::update_firefox,
            ],
        )
        .launch();
    Ok(())
}
