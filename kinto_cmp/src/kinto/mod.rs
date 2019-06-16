use reqwest::Url;
use serde::Deserialize;
use std::convert::TryFrom;

use crate::errors::*;

#[derive(Deserialize, Debug)]
pub struct Kinto {
    pub data: Vec<KintoEntry>,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct KintoEntry {
    pub schema: u64,
    pub details: KintoDetails,
    pub enabled: bool,
    pub issuerName: String,
    pub serialNumber: String,
    pub id: String,
    pub last_modified: u64,
}

#[derive(Deserialize, Debug)]
pub struct KintoDetails {
    pub bug: String,
    pub who: String,
    pub why: String,
    pub name: String,
    pub created: String,
}

impl TryFrom<Url> for Kinto {
    type Error = Error;

    fn try_from(url: Url) -> Result<Self> {
        let url_str = url.to_string();
        reqwest::Client::new()
            .get(url)
            .header("User-Agent", crate::USER_AGENT)
            .header("X-Automated-Tool", crate::X_AUTOMATED_TOOL)
            .send()
            .chain_err(|| format!("failed to download {}", url_str))?
            .json()
            .chain_err(|| format!("failed to deserialize Kinto"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;
    use reqwest::Url;
    use std::convert::TryInto;

    #[test]
    fn smoke() -> Result<()> {
        let _: Kinto = KINTO
            .parse::<Url>()
            .chain_err(|| "bad Kinto URL")?
            .try_into()?;
        Ok(())
    }
}
