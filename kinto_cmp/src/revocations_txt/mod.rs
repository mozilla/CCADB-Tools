use std::collections::HashMap;
use std::convert::{From, TryFrom};
use std::hash::{Hash, Hasher};

use crate::errors::*;
use crate::{Kinto, KintoEntry};
use reqwest::Url;
use std::fs::File;
use std::io::{BufRead, Read};

#[derive(Debug, Eq, PartialEq)]
pub struct Revocations {
    pub data: Vec<Revocation>,
}

impl Revocations {
    /// Rules for this parser were plucked from
    /// https://searchfox.org/mozilla-central/source/security/manager/ssl/tests/unit/test_onecrl/sample_revocations.txt
    ///
    /// If a key has is found an error is returned, as we do not have key hashes in Kinto
    /// thus finding one in revocations.txt would make life hard on us.
    pub fn parse(reader: Box<dyn Read>) -> Result<Revocations> {
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
    /// and that serial should be associated with the nearest issuer.
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
        let resp = reqwest::Client::new()
            .get(url)
            .header("User-Agent", crate::USER_AGENT)
            .header("X-Automated-Tool", crate::X_AUTOMATED_TOOL)
            .send()
            .chain_err(|| format!("failed to download {}", url_str))?;
        Revocations::parse(Box::new(resp))
    }
}

impl TryFrom<File> for Revocations {
    type Error = Error;

    fn try_from(file: File) -> Result<Self> {
        Revocations::parse(Box::new(file))
    }
}

impl From<Kinto> for Revocations {
    fn from(mut kinto: Kinto) -> Self {
        let mut revocations: HashMap<String, Revocation> = HashMap::new();
        for mut rev in kinto
            .data
            .drain(..)
            .map(|f| f.into())
            .collect::<Vec<Revocation>>()
        {
            if let Some(r) = revocations.get_mut(&rev.issuer_name) {
                r.serials.append(&mut rev.serials);
            } else {
                revocations.insert(rev.issuer_name.clone(), rev);
            }
        }
        Revocations {
            data: revocations.drain().map(|(_, v)| v).collect(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
#[allow(non_snake_case)]
pub struct Revocation {
    pub issuer_name: String,
    pub serials: Vec<String>,
}

impl std::convert::From<KintoEntry> for Revocation {
    fn from(ke: KintoEntry) -> Self {
        Revocation {
            issuer_name: ke.issuerName,
            serials: vec![ke.serialNumber],
        }
    }
}

impl Hash for Revocation {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.issuer_name.hash(state);
    }
}

impl Revocation {
    pub fn new(issuer_name: String) -> Revocation {
        return Revocation {
            issuer_name: issuer_name,
            serials: vec![],
        };
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
mod tests {

    use super::*;
    use crate::tests::*;
    use std::convert::TryInto;

    #[test]
    fn should_exactly_match() -> Result<()> {
        let got: Revocations = REVOCATIONS_TXT.parse::<Url>().unwrap().try_into()?;
        let want = reqwest::Client::new()
            .get(REVOCATIONS_TXT)
            .header("User-Agent", crate::USER_AGENT)
            .header("X-Automated-Tool", crate::X_AUTOMATED_TOOL)
            .send()
            .chain_err(|| format!("failed to download {}", REVOCATIONS_TXT))?
            .text()
            .unwrap();
        assert_eq!(got.serialize(), want);
        Ok(())
    }
}
