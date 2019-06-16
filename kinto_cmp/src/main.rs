#![feature(slice_patterns)]

#[macro_use]
extern crate error_chain;
extern crate reqwest;
extern crate structopt;

mod errors {
    error_chain! {}
}

use errors::*;
use reqwest::Url;
use std::collections::HashSet;
use std::convert::TryInto;
use structopt::StructOpt;

mod intermediary;
mod kinto;
mod revocations_txt;

use intermediary::*;
use kinto::*;
use revocations_txt::*;

const USER_AGENT: &str = "github.com/mozilla/CCADB-Tools/kinto_cmp chris@chenderson.org";
const X_AUTOMATED_TOOL: &str = "github.com/mozilla/CCADB-Tools/kinto_cmp";

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
}

fn main() -> Result<()> {
    let opts: KintoDiffRevocations = KintoDiffRevocations::from_args();
    let revocations: Revocations = opts.revocations.try_into()?;
    let kinto: Kinto = opts.kinto.try_into()?;
    let revocations: HashSet<Intermediary> = revocations.into();
    let kinto: HashSet<Intermediary> = kinto.into();
    println!("revocations.len() = {:#?}", revocations.len());
    println!("kinto.len() = {:#?}", kinto.len());
    println!(
        "revocations.symmetric_difference(&kinto) = {:#?}",
        revocations.symmetric_difference(&kinto)
    );
    Ok(())
}
