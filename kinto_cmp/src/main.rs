#![feature(slice_patterns)]

extern crate reqwest;
#[macro_use]
extern crate error_chain;

use serde::Deserialize;
use std::io::{BufRead, Cursor};

// We'll put our errors in an `errors` module, and other modules in
// this crate will `use errors::*;` to get access to everything
// `error_chain!` creates.
mod errors {
    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain! {}
}

// This only gives access within this module. Make this `pub use errors::*;`
// instead if the types must be accessible from other modules (e.g., within
// a `links` section).
use errors::*;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::hash::{Hash, Hasher};

extern crate itertools;
use itertools::Itertools;

const REVOCATIONS_TXT: &str = "https://bug1553256.bmoattachments.org/attachment.cgi?id=9066502";
const KINTO: &str =
    "https://settings.prod.mozaws.net/v1/buckets/security-state/collections/onecrl/records";

fn main() -> Result<()> {
    let mut revocations: Revocations = parse_revocations_txt(&download_revocations_txt(REVOCATIONS_TXT)?)?;
    let mut kinto: Revocations = download_kinto(KINTO)?.into();
//    eprintln!("kinto.data.size = {:#?}", kinto.data.len());
//    eprintln!("kinto.data.size = {:#?}", revocations.data.len());
    revocations.data.iter_mut().for_each(|r| {r.serials.sort(); r.serials = r.serials.drain(..).unique().collect()});
    kinto.data.iter_mut().for_each(|r| {r.serials.sort(); r.serials = r.serials.drain(..).unique().collect()});
    eprintln!("revocations.eq(&kinto) = {:#?}", revocations.eq(&kinto));
    let rhash: HashSet<Revocation> = HashSet::from_iter(revocations.data.drain(..));
    let khash: HashSet<Revocation> = HashSet::from_iter(kinto.data.drain(..));
    eprintln!("rhash.difference(&khash) = {:#?}", rhash.difference(&khash));
    eprintln!("rhash.difference(&khash) = {:#?}", khash.difference(&rhash));
    Ok(())
}

fn download_revocations_txt(url: &str) -> Result<String> {
    reqwest::Client::new()
        .get(url)
        .header(
            "User-Agent",
            "github.com/mozilla/revocations chris@chenderson.org",
        )
        .header("X-Automated-Tool", "github.com/mozilla/revocations")
        .send()
        .chain_err(|| format!("failed to download {}", url))?
        .text()
        .chain_err(|| format!("failed to get the textual body from {}", url))
}

fn parse_revocations_txt(content: &String) -> Result<Revocations> {
    let mut revocations = Revocations::new();
    let mut buf = Cursor::new(content);
    loop {
        let mut line = String::new();
        match buf.read_line(&mut line) {
            Ok(0) => return Ok(revocations),
            Ok(_) => (),
            Err(err) => Err(err).chain_err(|| "failed read line from revocations.txt")?,
        }
        match line.as_bytes() {
            [b'#', ..] => (),       // Comment
            [b' ', b' ', ..] => (), // Empty Line
            [b'\t', ..] => Err(format!("found a hash {:?}", line))?,
            [b' ', serial.., b'\n'] => revocations.push_serial(serial)?,
            [issuer.., b'\n'] => revocations.push_issuer(issuer)?,
            [..] => Err(format!("unknown line {}", line))?,
        }
    }
}

fn download_kinto(url: &str) -> Result<Kinto> {
    reqwest::Client::new()
        .get(url)
        .header(
            "User-Agent",
            "github.com/mozilla/revocations chris@chenderson.org",
        )
        .header("X-Automated-Tool", "github.com/mozilla/revocations")
        .send()
        .chain_err(|| format!("failed to download {}", url))?
        .json()
        .chain_err(|| format!("failed to parse Kinto JSON from {}", url))
}

#[derive(Debug, Eq, PartialEq)]
struct Revocations {
    pub data: Vec<Revocation>,
}

impl Revocations {
    pub fn new() -> Revocations {
        Revocations { data: vec![] }
    }

    pub fn push_issuer(&mut self, issuer: &[u8]) -> Result<()> {
        let i =
            String::from_utf8(issuer.to_vec()).chain_err(|| "ut8 conversion failed for serial")?;
        self.data.push(Revocation::new(i));
        Ok(())
    }

    pub fn push_serial(&mut self, serial: &[u8]) -> Result<()> {
        let s =
            String::from_utf8(serial.to_vec()).chain_err(|| "ut8 conversion failed for serial")?;
        if let Some(mut issuer) = self.data.pop() {
            issuer.serials.push(s);
            self.data.push(issuer);
            Ok(())
        } else {
            Err(format!("No issuer associated with serial {}", s))?
        }
    }

    #[allow(dead_code)]
    pub fn serialize(&self) -> String {
        let mut s = String::new();
        s.push_str("# Auto generated contents. Do not edit.\n");
        for revocation in self.data.iter() {
            s.push_str(revocation.serialize().as_str());
        }
        s
    }
}

impl std::convert::From<Kinto> for Revocations {
    fn from(mut kinto: Kinto) -> Self {
        let mut revocations:  HashMap<String, Revocation> = HashMap::new();
        for mut rev in kinto.data.drain(..).map(|f| f.into()).collect::<Vec<Revocation>>() {
            if let Some(r) = revocations.get_mut(&rev.issuerName) {
                r.serials.append(&mut rev.serials);
            } else {
                revocations.insert(rev.issuerName.clone(), rev);
            }
        }
        Revocations{data: revocations.drain().map(|(_, v)| v).collect()}
    }
}

#[derive(Debug, Eq, PartialEq)]
#[allow(non_snake_case)]
struct Revocation {
    issuerName: String,
    serials: Vec<String>,
}

impl std::convert::From<KintoEntry> for Revocation {
    fn from(ke: KintoEntry) -> Self {
        Revocation{issuerName: ke.issuerName, serials: vec![ke.serialNumber]}
    }
}

impl Hash for Revocation {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.issuerName.hash(state);
    }
}

impl Revocation {
    pub fn new(issuer_name: String) -> Revocation {
        return Revocation {
            issuerName: issuer_name,
            serials: vec![],
        };
    }

    #[allow(dead_code)]
    pub fn serialize(&self) -> String {
        let mut s = String::new();
        s.push_str(self.issuerName.as_str());
        s.push('\n');
        for serial in self.serials.iter() {
            s.push(' ');
            s.push_str(serial.as_str());
            s.push('\n');
        }
        s
    }
}

#[derive(Deserialize, Debug)]
struct Kinto {
    pub data: Vec<KintoEntry>,
}

//impl Kinto {
//    pub fn into(&self) -> Revocations {
//        let mut revocations:  HashMap<String, Revocation> = HashMap::new();
//        for entry in self.data.iter() {
//            let mut rev: Revocation = entry.into();
//            if let Some(r) = revocations.get_mut(&rev.issuerName) {
//                r.serials.append(&mut rev.serials);
//            } else {
//                revocations.insert(rev.issuerName.clone(), rev);
//            }
//        }
//        Revocations{data: revocations.drain().map(|(_, v)| v).collect()}
//    }
//}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct KintoEntry {
    pub schema: u64,
    pub details: KintoDetails,
    pub enabled: bool,
    pub issuerName: String,
    pub serialNumber: String,
    pub id: String,
    pub last_modified: u64,
}

//impl KintoEntry {
//    pub fn into(&self) -> Revocation {
//        Revocation{issuerName: self.issuerName.clone(), serials: vec![self.serialNumber.clone()]}
//    }
//}

#[derive(Deserialize, Debug)]
struct KintoDetails {
    pub bug: String,
    pub who: String,
    pub why: String,
    pub name: String,
    pub created: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{BufRead, Read};
    //    use byteorder::io::ReadBytesExt;
    //    use std::io::prelude::*;
    #[test]
    fn asdas() {
        let content = String::new();
        let mut buf = std::io::Cursor::new(content);
        eprintln!("buf.read_u8() = {:#?}", buf.read_line(&mut String::new()));
        eprintln!("buf = {:#?}", buf.take(1).read(&mut vec![]));
    }

    fn is_symmetric(list: &[u32]) -> bool {
        match list {
            [] | [_] => true,
            [x, inside.., y] if x == y => is_symmetric(inside),
            _ => false,
        }
    }
    #[test]
    fn asdasd() {
        let sym = &[0, 1, 4, 2, 4, 1, 0];
        assert!(is_symmetric(sym));

        let not_sym = &[0, 1, 7, 2, 4, 1, 0];
        assert!(!is_symmetric(not_sym));
    }
}
