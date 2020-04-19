/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::convert::TryFrom;

use crate::errors::*;
use crate::http;
use crate::model::Revocation;
use rayon::prelude::*;
use reqwest::Url;
use rocket::data::DataStream;
use std::collections::hash_map::RandomState;
use std::collections::HashSet;
use std::io::{BufRead, Cursor, Read};

pub(crate) const REVOCATIONS_TXT: &str = include_str!("revocations.txt");

pub struct Revocations {
    pub data: Vec<Entry>,
}

impl Into<HashSet<crate::model::Revocation>> for Revocations {
    fn into(self) -> HashSet<Revocation, RandomState> {
        self.data
            .into_par_iter()
            .map(|entry| entry.into())
            .collect()
    }
}

impl Revocations {
    pub fn default() -> IntegrityResult<Revocations> {
        Revocations::try_from(REVOCATIONS_TXT)
    }

    /// Rules for this parser were plucked from
    /// https://searchfox.org/mozilla-central/source/security/manager/ssl/tests/unit/test_onecrl/sample_revocations.txt
    ///
    /// If a key hash is found an error is returned, as we do not have key hashes in Kinto,
    /// thus finding one in revocations.txt would make life hard on us.
    pub fn parse<R: Read>(&mut self, reader: R) -> IntegrityResult<()> {
        let mut buf = std::io::BufReader::new(reader);
        let mut lineno = 0;
        loop {
            lineno += 1;
            let mut line = String::new();
            match buf.read_line(&mut line) {
                Ok(0) => return Ok(()),
                Ok(_) => (),
                Err(err) => Err(err).map_err(|err| {
                    IntegrityError::new("failed read a line from revocations.txt").with_err(err)
                })?,
            }
            match line.as_bytes() {
                [b'#', ..] => (),         // Comment
                [b' ', b' ', ..] => (),   // Whitespace Line
                [b'\t', b'\t', ..] => (), // Tab whitespace line
                [] => (),                 // Empty Line
                [b'\t', hash @ .., b'\n'] => {
                    return Err(IntegrityError::new(
                        "found a key hash before a any subject could be associated with it",
                    )
                    .with_context(ctx!(("hash", String::from_utf8(Vec::from(hash)).unwrap()))))
                }
                [b' ', serial @ .., b'\n'] => {
                    return Err(IntegrityError::new(
                        "found a serial before a any issuer could be associated with it",
                    )
                    .with_context(ctx!((
                        "serial",
                        String::from_utf8(Vec::from(serial)).unwrap()
                    ))))
                }
                [name @ .., b'\n'] => return self._parse(buf, name, lineno),
                [..] => Err(format!("unknown entry type at line {}, {}", lineno, line))?,
            }
        }
    }

    pub fn _parse<R: Read>(
        &mut self,
        mut buf: std::io::BufReader<R>,
        name: &[u8],
        mut lineno: u32,
    ) -> IntegrityResult<()> {
        let name = String::from_utf8(Vec::from(name)).map_err(|err| {
            IntegrityError::new("A name in revocations.txt failed to parse to valid UTF8")
                .with_err(err)
                .with_context(ctx!(("line", String::from_utf8_lossy(name).to_string())))
        })?;
        loop {
            lineno += 1;
            let mut line = String::new();
            match buf.read_line(&mut line) {
                Ok(0) => return Ok(()),
                Ok(_) => (),
                Err(err) => Err(err).map_err(|err| {
                    IntegrityError::new("failed read a line from revocations.txt").with_err(err)
                })?,
            }
            match line.as_bytes() {
                [b'#', ..] => (),         // Comment
                [b' ', b' ', ..] => (),   // Whitespace Line
                [b'\t', b'\t', ..] => (), // Tab whitespace line
                [] => (),                 // Empty Line
                [b'\t', hash @ .., b'\n'] => self.data.push(Entry::SubjectKeyHash {
                    subject: name.clone(),
                    key_hash: String::from_utf8_lossy(hash).to_string(),
                }),
                [b' ', serial @ .., b'\n'] => self.data.push(Entry::IssuerSerial {
                    issuer: name.clone(),
                    serial: String::from_utf8_lossy(serial).to_string(),
                }),
                [next_name @ .., b'\n'] => return self._parse(buf, next_name, lineno),
                [..] => Err(format!("unknown entry type at line {}, {}", lineno, line))?,
            }
        }
    }
}

impl TryFrom<Url> for Revocations {
    type Error = IntegrityError;

    fn try_from(url: Url) -> IntegrityResult<Self> {
        let url_str = url.to_string();
        let resp = http::new_get_request(url).send().map_err(|err| {
            IntegrityError::new(
                "Could not establish a connection to download a copy of revocations.txt",
            )
            .with_err(err)
            .with_context(ctx!(("url", url_str.clone())))
        })?;
        let mut rev = Revocations { data: vec![] };
        rev.parse(resp)?;
        Ok(rev)
    }
}

impl TryFrom<DataStream> for Revocations {
    type Error = IntegrityError;

    fn try_from(value: DataStream) -> IntegrityResult<Self> {
        let mut rev = Revocations { data: vec![] };
        rev.parse(value)?;
        Ok(rev)
    }
}

impl TryFrom<&str> for Revocations {
    type Error = IntegrityError;

    fn try_from(value: &str) -> IntegrityResult<Self> {
        let mut rev = Revocations { data: vec![] };
        rev.parse(Cursor::new(String::from(value)))?;
        Ok(rev)
    }
}

impl TryFrom<String> for Revocations {
    type Error = IntegrityError;

    fn try_from(value: String) -> IntegrityResult<Self> {
        let mut rev = Revocations { data: vec![] };
        rev.parse(Cursor::new(value))?;
        Ok(rev)
    }
}

pub enum Entry {
    IssuerSerial { issuer: String, serial: String },
    SubjectKeyHash { subject: String, key_hash: String },
}

impl Into<crate::model::Revocation> for Entry {
    fn into(self) -> Revocation {
        match self {
            Entry::IssuerSerial { issuer, serial } => {
                Revocation::new_issuer_serial(issuer, serial, None)
            }
            Entry::SubjectKeyHash { subject, key_hash } => {
                Revocation::new_subject_key_hash(subject, key_hash, None)
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn e2e() {
        for entry in Revocations::default().unwrap().data {
            match entry {
                Entry::IssuerSerial {
                    issuer: _,
                    serial: _,
                } => (),
                Entry::SubjectKeyHash {
                    subject: s,
                    key_hash: h,
                } => println!("{} {}", s, h),
            }
        }
    }
}
