use std::path::{Path, PathBuf};
use std::convert::{TryFrom, TryInto};
use reqwest::Url;
use reqwest::Client;

use tempdir::TempDir;

use rand;

use lazy_static;

use crate::errors::*;
use std::io::BufReader;
use std::sync::Mutex;
use std::process::Command;

lazy_static!(
    pub static ref NIGHTLY: Url = "https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=linux64&lang=en-US".parse().unwrap();
    pub static ref FIREFOX: Mutex<Firefox> = Mutex::new(Firefox{path: PathBuf::new()});
);

//pub const NIGHTLY: &str = "https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=linux64&lang=en-US";

pub struct Firefox {
    path: PathBuf
}

impl Firefox {

    pub fn init_profile(&self) -> TempDir {
        let profile  = tempdir::TempDir::new("kinto_diff_ccadb").unwrap();
        let executable = self.path.join("firefox").to_string_lossy(),;
        let profile_name = format!("{:x}", rand::random:<u32>:());
        let profile_location = profile.path().to_string_lossy();
        let cmd  = format!(
            r#"{} -CreateProfile "{:x} {}""#,
            executable, profile_name, profile_location);
        println!("{}", cmd);
        Command::new(cmd).env("DISPLAY", ":99").spawn().unwrap();
        let cmd = format!("{} -P {}", executable, profile_name);
        Command::new(cmd).env("DISPLAY", ":99").spawn().
        profile
    }

    pub fn from_nightly() -> Result<Firefox> {
        (*NIGHTLY).clone().try_into()
    }
}

impl Drop for Firefox {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path);
    }
}

impl TryFrom<Url> for Firefox {
    type Error = Error;

    fn try_from(value: Url) -> Result<Self> {
        let resp = Client::new().get(value).header("X-AUTOMATED-TOOL", "ccadb").send()?;
        let path = PathBuf::from(r#"H:\CCADB-Tools\perhaps"#);
        tar::Archive::new(bzip2::bufread::BzDecoder::new(BufReader::new(resp))).unpack(&path)?;
        return Ok(Firefox{path: path});
    }
}

impl TryFrom<&str> for Firefox {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        value.parse::<Url>().unwrap().try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn asdfgsd() {
        Firefox{path: PathBuf::from(r#"/usr/lol/tmp/"#)}.init_profile();
    }

    #[test]
    fn smoke() {
        let ff: Firefox = (*NIGHTLY).clone().try_into().unwrap();
    }
}