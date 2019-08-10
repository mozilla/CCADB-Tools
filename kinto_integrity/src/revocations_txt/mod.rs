/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::convert::TryFrom;

use crate::errors::*;
use crate::http;
use reqwest::Url;
use std::io::{BufRead, Cursor, Read};

const REVOCATIONS_TXT: &str = include_str!("revocations.txt");

pub struct Revocations {
    pub data: Vec<Revocation>,
}

impl Revocations {
    pub fn default() -> Result<Revocations> {
        Revocations::parse(Cursor::new(REVOCATIONS_TXT))
    }

    /// Rules for this parser were plucked from
    /// https://searchfox.org/mozilla-central/source/security/manager/ssl/tests/unit/test_onecrl/sample_revocations.txt
    ///
    /// If a key hash is found an error is returned, as we do not have key hashes in Kinto,
    /// thus finding one in revocations.txt would make life hard on us.
    pub fn parse<R: Read>(reader: R) -> Result<Revocations> {
        let mut revocations = Revocations { data: vec![] };
        let mut buf = std::io::BufReader::new(reader);
        let mut lineno = 0;
        loop {
            lineno += 1;
            let mut line = String::new();
            match buf.read_line(&mut line) {
                Ok(0) => return Ok(revocations),
                Ok(_) => (),
                Err(err) => Err(err).chain_err(|| "failed read line from revocations.txt")?,
            }
            match line.as_bytes() {
                [b'#', ..] => (),         // Comment
                [b' ', b' ', ..] => (),   // Whitespace Line
                [b'\t', b'\t', ..] => (), // Tab whitespace line
                [] => (),                 // Empty Line
                [b'\t', ..] => Err(format!("found a hash {:?}", line))?,
                [b' ', .., b'\n'] => revocations.push_serial(line)?,
                [.., b'\n'] => revocations.push_issuer(line),
                [..] => Err(format!("unknown entry type at line {}, {}", lineno, line))?,
            }
        }
    }

    fn push_issuer(&mut self, issuer: String) {
        self.data.push(Revocation::new(issuer.trim().to_string()));
    }

    /// This parser is banking on the following structure
    ///
    /// issuer
    ///  serial
    ///  serial
    ///  serial
    ///  ...
    /// issuer
    ///
    /// Which is to say, we're assuming that an issuer comes before any given serial,
    /// and that that serial should be associated with the nearest issuer.
    ///
    /// If a serial is found without a nearest issuer, then an error is returned.
    fn push_serial(&mut self, serial: String) -> Result<()> {
        match self.data.pop() {
            Some(mut issuer) => {
                issuer.serials.push(serial.trim().to_string());
                self.data.push(issuer);
                Ok(())
            }
            None => Err(format!("No issuer associated with serial {}", serial))?,
        }
    }

    /// Puts revocations.txt back exactly the way it was.
    /// Used primarily for building a convincing test.
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

impl TryFrom<Url> for Revocations {
    type Error = Error;

    fn try_from(url: Url) -> Result<Self> {
        let url_str = url.to_string();
        let resp = http::new_get_request(url)
            .send()
            .chain_err(|| format!("failed to download {}", url_str))?;
        Revocations::parse(resp)
    }
}

impl TryFrom<String> for Revocations {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Revocations::parse(Cursor::new(value))
    }
}

pub struct Revocation {
    pub issuer_name: String,
    pub serials: Vec<String>,
}

impl Revocation {
    pub fn new(issuer_name: String) -> Revocation {
        Revocation {
            issuer_name,
            serials: vec![],
        }
    }

    #[allow(dead_code)]
    pub fn serialize(&self) -> String {
        let mut s = String::new();
        s.push_str(self.issuer_name.as_str());
        s.push('\n');
        for serial in self.serials.iter() {
            s.push(' ');
            s.push_str(serial.as_str());
            s.push('\n');
        }
        s
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;
    use std::convert::TryInto;

    pub const REVOCATIONS_TXT: &str =
        "https://bug1553256.bmoattachments.org/attachment.cgi?id=9066502";

    #[test]
    /// Parses and then reconstructs revocations.txt, asserting that the reconstructed
    /// value is exactly the same as
    fn smoke_revocations_txt() -> Result<()> {
        let got: Revocations = REVOCATIONS_TXT.parse::<Url>().unwrap().try_into()?;
        let want = http::new_get_request(REVOCATIONS_TXT.parse::<Url>().unwrap())
            .send()
            .chain_err(|| format!("failed to download {}", REVOCATIONS_TXT))?
            .text()
            .unwrap();
        assert_eq!(got.serialize(), want);
        Ok(())
    }
}
