use reqwest::Url;
use serde::Deserialize;
use std::convert::TryFrom;

use crate::errors::*;

#[derive(Deserialize, Debug)]
pub struct Kinto {
    pub data: Vec<KintoEntry>,
}

#[derive(Deserialize, Debug)]
pub struct KintoEntry {
    pub schema: u64,
    pub details: KintoDetails,
    pub enabled: bool,
    #[serde(rename = "issuerName")]
    pub issuer_name: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
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
pub(crate) mod tests {
    use super::*;
    use reqwest::Url;
    use std::convert::TryInto;
    use std::collections::HashSet;
    use crate::intermediary::Intermediary;

    pub const KINTO: &str =
        "https://settings.prod.mozaws.net/v1/buckets/security-state/collections/onecrl/records";

    #[test]
    fn smoke() -> Result<()> {
        let _: Kinto = KINTO
            .parse::<Url>()
            .chain_err(|| "bad Kinto URL")?
            .try_into()?;
        Ok(())
    }

    #[test]
    /// This points out that, when only considering issuerName/serial that Kinto has the following
    /// duplicates. They do have unique last_modified and ids, but I don't know what these mean.
    ///
    /// entry = KintoEntry {
	///    schema: 1552492993020,
	///    details: KintoDetails {
	///        bug: "https://bugzilla.mozilla.org/show_bug.cgi?id=1487485",
	///        who: "",
	///        why: "",
	///        name: "",
	///        created: "2018-08-30T11:09:06Z",
	///    },
	///    enabled: true,
	///    issuer_name: "MF0xCzAJBgNVBAYTAkpQMSUwIwYDVQQKExxTRUNPTSBUcnVzdCBTeXN0ZW1zIENPLixMVEQuMScwJQYDVQQLEx5TZWN1cml0eSBDb21tdW5pY2F0aW9uIFJvb3RDQTI=",
	///    serial_number: "IrmxST2Fhyj5",
	///    id: "752a5350-9895-434e-abe7-04b85863341e",
	///    last_modified: 1535652551184,
	///	}	
	///	entry = KintoEntry {
	///	    schema: 1552492994435,
	///	    details: KintoDetails {
	///	        bug: "https://bugzilla.mozilla.org/show_bug.cgi?id=1487485",
	///	        who: "",
	///	        why: "",
	///	        name: "",
	///	        created: "2018-08-30T11:09:06Z",
	///	    },
	///	    enabled: true,
	///	    issuer_name: "MDwxHjAcBgNVBAMMFUF0b3MgVHJ1c3RlZFJvb3QgMjAxMTENMAsGA1UECgwEQXRvczELMAkGA1UEBhMCREU=",
	///	    serial_number: "W2qOjVqGcY8=",
	///	    id: "724dc57b-1305-4bc3-82af-90d7457e08b7",
	///	    last_modified: 1535652548311,
	///	}
	///	entry = KintoEntry {
	///	    schema: 1552492994435,
	///	    details: KintoDetails {
	///	        bug: "https://bugzilla.mozilla.org/show_bug.cgi?id=1487485",
	///	        who: "",
	///	        why: "",
	///	        name: "",
	///	        created: "2018-08-30T11:09:06Z",
	///	    },
	///	    enabled: true,
	///	    issuer_name: "MDwxHjAcBgNVBAMMFUF0b3MgVHJ1c3RlZFJvb3QgMjAxMTENMAsGA1UECgwEQXRvczELMAkGA1UEBhMCREU=",
	///	    serial_number: "W2qOjVqGcY8=",
	///	    id: "aa81cbe1-031c-4e40-b2d1-e6b9ec6abd7e",
	///	    last_modified: 1535652547990,
	///	}
	///	entry = KintoEntry {
	///	    schema: 1552493008615,
	///	    details: KintoDetails {
	///	        bug: "https://bugzilla.mozilla.org/show_bug.cgi?id=1420411",
	///	        who: "",
	///	        why: "",
	///	        name: "",
	///	        created: "2017-11-24T13:38:55Z",
	///	    },
	///	    enabled: true,
	///	    issuer_name: "MEUxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxHzAdBgNVBAMTFlN3aXNzU2lnbiBHb2xkIENBIC0gRzI=",
	///	    serial_number: "AIQ8dLGqNIaxxMeg31W16Q==",
	///	    id: "8a10108d-b91c-49da-9748-72421d965126",
	///	    last_modified: 1511530740428,
	///	}
    fn find_duplicates() -> Result<()> {
        let kinto: Kinto = KINTO
            .parse::<Url>()
            .chain_err(|| "bad Kinto URL")?
            .try_into()?;
        let mut set= HashSet::new();
        for entry in kinto.data.into_iter() {
            let int = Intermediary{issuer_name: entry.issuer_name.clone(), serial: entry.serial_number.clone()};
            match set.contains(&int) {
                true => eprintln!("entry = {:#?}", entry),
                false => {set.insert(int);}
            };
        }
        Ok(())
    }
}
