use std::collections::HashSet;
use std::convert::From;

use crate::revocations_txt::*;
use crate::kinto::Kinto;

#[derive(Eq, PartialEq, Hash, Debug)]
pub struct Intermediary {
    pub issuer_name: String,
    pub serial: String,
}

impl From<Revocations> for HashSet<Intermediary> {
    /// Flattens out:
    ///     issuer
    ///      serial
    ///      serial
    ///      serial
    /// To:
    ///     [(issuer, serial), (issuer, serial), (issuer, serial)]
    fn from(revocations: Revocations) -> Self {
        let mut set: HashSet<Intermediary> = HashSet::new();
        for issuer in revocations.data.into_iter() {
            for serial in issuer.serials.into_iter() {
                set.insert(Intermediary {
                    issuer_name: issuer.issuer_name.clone(),
                    serial: serial,
                });
            }
        }
        set
    }
}

impl From<Kinto> for HashSet<Intermediary> {
    /// The interesting thing to point out here is that Kinto has
    /// many duplicate issuer/serial pairs for which I am not keen
    /// as to the purpose.
    fn from(kinto: Kinto) -> Self {
        let mut set: HashSet<Intermediary> = HashSet::new();
        for entry in kinto.data.into_iter() {
            set.insert(Intermediary{
                issuer_name: entry.issuerName,
                serial: entry.serialNumber
            });
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;
    use crate::errors::*;
    use crate::tests::*;
    use reqwest::Url;

    #[test]
    fn smoke_from_revocations() -> Result<()> {
        let rev: Revocations = REVOCATIONS_TXT.parse::<Url>().chain_err(|| "bad URL")?.try_into()?;
        let int: HashSet<Intermediary> = rev.into();
        eprintln!("int = {:#?}", int);
        Ok(())
    }

    #[test]
    fn smoke_from_kinto() -> Result<()> {
        let kinto: Kinto = KINTO.parse::<Url>().chain_err(|| "bad URL")?.try_into()?;
        let int: HashSet<Intermediary> = kinto.into();
        eprintln!("int = {:#?}", int);
        Ok(())
    }
}
