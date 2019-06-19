/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![feature(slice_patterns)]

#[macro_use]
extern crate error_chain;
extern crate reqwest;
extern crate structopt;
extern crate lmdb;
extern crate rkv;

use std::collections::HashSet;
use std::convert::TryInto;

use reqwest::Url;
use structopt::StructOpt;

mod cert_storage;
mod intermediary;
mod kinto;
mod revocations_txt;

mod errors {
    error_chain! {}
}

use cert_storage::*;
use errors::*;
use intermediary::*;
use kinto::*;
use revocations_txt::*;
use std::path::PathBuf;

const USER_AGENT: &str = "github.com/mozilla/CCADB-Tools/kinto_integrity chris@chenderson.org";
const X_AUTOMATED_TOOL: &str = "github.com/mozilla/CCADB-Tools/kinto_integrity";

#[derive(StructOpt)]
struct KintoDiffRevocations {
    #[structopt(
        short = "r",
        long = "revocations",
        default_value = "https://bug1553256.bmoattachments.org/attachment.cgi?id=9066502"
    )]
    revocations: Url,

    #[structopt(
        short = "k",
        long = "kinto",
        default_value = "https://settings.prod.mozaws.net/v1/buckets/security-state/collections/onecrl/records"
    )]
    kinto: Url,

    #[structopt(
        short = "p",
        long = "profile",
        default_value = r#"C:\Users\Christopher Henderso\AppData\Roaming\Mozilla\Firefox\Profiles\b1e6quep.default-nightly"#
    )]
    profile: PathBuf,
}

fn main() -> Result<()> {
    let opts: KintoDiffRevocations = KintoDiffRevocations::from_args();
    let revocations: Revocations = opts.revocations.try_into()?;
    let certstorage: CertStorage = opts.profile.try_into()?;
    let kinto: Kinto = opts.kinto.try_into()?;
    let revocations: HashSet<Intermediary> = revocations.into();
    let kinto: HashSet<Intermediary> = kinto.into();
    let cert_storage: HashSet<Intermediary> = certstorage.into();
    println!("revocations.len() = {:#?}", revocations.len());
    println!("kinto.len() = {:#?}", kinto.len());
    println!("cert_storage.len() = {:#?}", cert_storage.len());
    println!(
        "revocations.symmetric_difference(&kinto) = {:#?}",
        revocations.symmetric_difference(&kinto)
    );
    println!("revocations.symmetric_difference(&cert_storage) = {:#?}", revocations.symmetric_difference(&cert_storage));;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Asserts that the observations in https://bugzilla.mozilla.org/show_bug.cgi?id=1548159#c2
    /// Are in https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records
    fn test_kathleens_observation() -> Result<()> {
        let revocations: Kinto = "https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records".parse::<Url>().chain_err(|| "bad URL")?.try_into()?;
        let revocations: HashSet<Intermediary> = revocations.into();
        let mut kathleens: HashSet<Intermediary> = HashSet::new();
        kathleens.insert(Intermediary{
            issuer_name: "MDsxCzAJBgNVBAYTAkVTMREwDwYDVQQKDAhGTk1ULVJDTTEZMBcGA1UECwwQQUMgUkFJWiBGTk1ULVJDTQ==".to_string(),
            serial: "RV864VwhzbpUT4KqR1Hr2w==".to_string()
        });
        kathleens.insert(Intermediary{
            issuer_name: "MIGxMQswCQYDVQQGEwJUUjEPMA0GA1UEBwwGQW5rYXJhMU0wSwYDVQQKDERUw5xSS1RSVVNUIEJpbGdpIMSwbGV0acWfaW0gdmUgQmlsacWfaW0gR8O8dmVubGnEn2kgSGl6bWV0bGVyaSBBLsWeLjFCMEAGA1UEAww5VMOcUktUUlVTVCBFbGVrdHJvbmlrIFNlcnRpZmlrYSBIaXptZXQgU2HEn2xhecSxY8Sxc8SxIEg1".to_string(),
            serial: "AZkNBFXrl1Zg".to_string()
        });
        kathleens.insert(Intermediary{
            issuer_name: "MIGxMQswCQYDVQQGEwJUUjEPMA0GA1UEBwwGQW5rYXJhMU0wSwYDVQQKDERUw5xSS1RSVVNUIEJpbGdpIMSwbGV0acWfaW0gdmUgQmlsacWfaW0gR8O8dmVubGnEn2kgSGl6bWV0bGVyaSBBLsWeLjFCMEAGA1UEAww5VMOcUktUUlVTVCBFbGVrdHJvbmlrIFNlcnRpZmlrYSBIaXptZXQgU2HEn2xhecSxY8Sxc8SxIEg1".to_string(),
            serial: "Aay2vr4aoUeZ".to_string()
        });
        kathleens.insert(Intermediary{
            issuer_name: "MIGxMQswCQYDVQQGEwJUUjEPMA0GA1UEBwwGQW5rYXJhMU0wSwYDVQQKDERUw5xSS1RSVVNUIEJpbGdpIMSwbGV0acWfaW0gdmUgQmlsacWfaW0gR8O8dmVubGnEn2kgSGl6bWV0bGVyaSBBLsWeLjFCMEAGA1UEAww5VMOcUktUUlVTVCBFbGVrdHJvbmlrIFNlcnRpZmlrYSBIaXptZXQgU2HEn2xhecSxY8Sxc8SxIEg1".to_string(),
            serial: "AUMyuCiycPJJ".to_string()
        });
        kathleens.insert(Intermediary{
            issuer_name: "MFoxCzAJBgNVBAYTAklFMRIwEAYDVQQKEwlCYWx0aW1vcmUxEzARBgNVBAsTCkN5YmVyVHJ1c3QxIjAgBgNVBAMTGUJhbHRpbW9yZSBDeWJlclRydXN0IFJvb3Q=".to_string(),
            serial: "ByeLBg==".to_string()
        });
        for observation in kathleens.iter() {
            assert!(revocations.contains(observation));
        }
        Ok(())
    }
}
