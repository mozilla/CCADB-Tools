/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::convert::TryFrom;

use crate::errors::*;
use crate::http;
use reqwest::Url;
use std::io::{BufRead, Cursor, Read};
use std::ops::Add;
use std::collections::HashSet;
use crate::model::Revocation;
use std::collections::hash_map::RandomState;

const REVOCATIONS_TXT: &str = include_str!("revocations_hash.txt");

pub struct Revocations {
    pub data: Vec<Entry>,
}

impl Into<HashSet<crate::model::Revocation>> for Revocations {
    fn into(self) -> HashSet<Revocation, RandomState> {
        self.data.into_iter().map(|entry| entry.into()).collect()
    }
}

impl Revocations {
    pub fn default() -> Result<Revocations> {
        Revocations::try_from(REVOCATIONS_TXT)
    }

    /// Rules for this parser were plucked from
    /// https://searchfox.org/mozilla-central/source/security/manager/ssl/tests/unit/test_onecrl/sample_revocations.txt
    ///
    /// If a key hash is found an error is returned, as we do not have key hashes in Kinto,
    /// thus finding one in revocations.txt would make life hard on us.
    pub fn parse<R: Read>(&mut self, reader: R) -> Result<()> {
        let mut buf = std::io::BufReader::new(reader);
        let mut lineno = 0;
        loop {
            lineno += 1;
            let mut line = String::new();
            match buf.read_line(&mut line) {
                Ok(0) => return Ok(()),
                Ok(_) => (),
                Err(err) => Err(err).chain_err(|| "failed read line from revocations.txt")?,
            }
            match line.as_bytes() {
                [b'#', ..] => (),         // Comment
                [b' ', b' ', ..] => (),   // Whitespace Line
                [b'\t', b'\t', ..] => (), // Tab whitespace line
                [] => (),                 // Empty Line
                [b'\t', hash @ .., b'\n'] => return Err(format!("found the hash {} before a any subject could be associated with it", String::from_utf8(Vec::from(hash))?).into()),
                [b' ', serial @ .., b'\n'] => return Err(format!("found the serial {} before a any issuer could be associated with it", String::from_utf8(Vec::from(serial))?).into()),
                [name @ .., b'\n'] => return self._parse(buf, name, lineno),
                [..] => Err(format!("unknown entry type at line {}, {}", lineno, line))?,
            }
        }
    }

    pub fn _parse<R: Read>(&mut self, mut buf: std::io::BufReader<R>, name: &[u8], mut lineno: u32) -> Result<()> {
        let name = String::from_utf8(Vec::from(name))?;
        loop {
            lineno += 1;
            let mut line = String::new();
            match buf.read_line(&mut line) {
                Ok(0) => return Ok(()),
                Ok(_) => (),
                Err(err) => Err(err).chain_err(|| "failed read line from revocations.txt")?,
            }
            match line.as_bytes() {
                [b'#', ..] => (),         // Comment
                [b' ', b' ', ..] => (),   // Whitespace Line
                [b'\t', b'\t', ..] => (), // Tab whitespace line
                [] => (),                 // Empty Line
                [b'\t', hash @ .., b'\n'] => self.data.push(Entry::SubjectKeyHash { subject: name.clone(), key_hash: String::from_utf8(Vec::from(hash))? }),
                [b' ', serial @ .., b'\n'] => self.data.push(Entry::IssuerSerial { issuer: name.clone(), serial: String::from_utf8(Vec::from(serial))? }),
                [next_name @ .., b'\n'] => return self._parse(buf, next_name, lineno),
                [..] => Err(format!("unknown entry type at line {}, {}", lineno, line))?,
            }
        }
    }
}

impl TryFrom<Url> for Revocations {
    type Error = Error;

    fn try_from(url: Url) -> Result<Self> {
        let url_str = url.to_string();
        let resp = http::new_get_request(url)
            .send()
            .chain_err(|| format!("failed to download {}", url_str))?;
        let mut rev = Revocations{data: vec![]};
        rev.parse(resp)?;
        Ok(rev)
    }
}
impl TryFrom<&str> for Revocations {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        let mut rev = Revocations{data: vec![]};
        rev.parse(Cursor::new(String::from(value)));
        Ok(rev)
    }
}


impl TryFrom<String> for Revocations {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        let mut rev = Revocations{data: vec![]};
        rev.parse(Cursor::new(value));
        Ok(rev)
    }
}

pub enum Entry {
    IssuerSerial {
        issuer: String,
        serial: String
    },
    SubjectKeyHash {
        subject: String,
        key_hash: String
    }
}

impl Into<crate::model::Revocation> for Entry {
    fn into(self) -> Revocation {
        match self {
            Entry::IssuerSerial { issuer, serial } =>
                Revocation::IssuerSerial{issuer, serial, sha_256: None},
            Entry::SubjectKeyHash { subject, key_hash } =>
                Revocation::SubjectKeyHash {subject, key_hash, sha_256: None}
        }
    }
}

impl Entry {
    fn issuer_serial_from(issuer: String, serial: String) -> Entry {
        Entry::IssuerSerial { issuer, serial }
    }

    fn subject_key_hash_from(subject: String, key_hash: String) -> Entry {
        Entry::SubjectKeyHash { subject, key_hash }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn e2e() {
        for entry in Revocations::default().unwrap().data {
            match entry {
                Entry::IssuerSerial{issuer: _, serial: _} => (),
                Entry::SubjectKeyHash{subject: s, key_hash: h} => {
                    println!("{} {}", s, h)
                }
            }
        }
    }
}