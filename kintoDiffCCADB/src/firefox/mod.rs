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
use std::process::{Command, Child};
use crate::firefox::profile::Profile;
use std::time::Duration;
use std::ffi::OsString;

mod profile;

lazy_static!(
    pub static ref NIGHTLY: Url = "https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=linux64&lang=en-US".parse().unwrap();
    pub static ref FIREFOX: Mutex<Firefox> = Mutex::new((*NIGHTLY).clone().try_into().unwrap());
);

const CREATE_PROFILE: &str = "-CreateProfile";
const WITH_PROFILE: &str = "-profile";
const NULL_DISPLAY_ENV: (&str, &str) = ("DISPLAY", ":99");

pub struct Firefox {
    home: TempDir,
    executable: OsString
}

impl Firefox {


    pub fn create_profile(&self) -> Result<Profile> {
        // Creates a name and system tmp directory for our profile.
        let profile = Profile::new()?;
        // Register the profile with Firefox.
        self.cmd().args(Firefox::create_profile_args(&profile)).output()?;
        // Startup Firefox with the given profile. Doing so will initialize the entire
        // profile to a fresh state and begin populating the cert_storage database.
        let mut cmd = self.cmd().args(Firefox::init_profile_args(&profile)).spawn()?;
        // Unfortunately, it's not like Firefox is giving us update progress over stdout,
        // so in order to be notified if cert storage is done being populate we gotta
        // listen in on the file and check up on its size.
        let database = || {
             std::fs::metadata(profile.cert_storage())
        };
        // Spin until it's created.
        while let Err(_) = database() {
            std::thread::sleep(Duration::from_millis(500));
        }
        // Spin until we are reasonably sure that it is populated.
        // This is only a heuristic and is not necessarily correct.
        let mut size = 0;
        let mut counter = 0;
        let mut error = None;
        loop {
            match database() {
                Err(err) => {
                    error = Some(Err(Error::from(err)));
                    break;
                }
                Ok(db) => {
                    let current = db.len();
                    match current {
                        size => counter += 1,
                        _ => {
                            size = current;
                            counter = 0;
                        }
                    };
                    if counter >= 100 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
        // Child does not implement drop in a meaningful way, so
        // we must be careful to not return early without first
        // cleaning it up.
        println!("asdasd");
        cmd.kill();
        println!("gggggg");
        match error {
            None => Ok(profile),
            Some(err) => err
        }
    }

    pub fn from_nightly() -> Result<Firefox> {
        (*NIGHTLY).clone().try_into()
    }

    fn create_profile_args(profile: &Profile) -> Vec<String> {
        vec![CREATE_PROFILE.to_string(), format!(r#"{} {}"#, profile.name, profile.home)]
    }

    fn init_profile_args(profile: &Profile) -> Vec<String> {
        vec![WITH_PROFILE.to_string(), profile.home.clone()]
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(&self.executable);
        cmd.env(NULL_DISPLAY_ENV.0, NULL_DISPLAY_ENV.1);
        cmd
    }
}

impl TryFrom<Url> for Firefox {
    type Error = Error;

    fn try_from(value: Url) -> Result<Self> {
        let home = TempDir::new("")?;
        let executable = home.path().join("firefox").join("firefox").into_os_string();
        let resp = Client::new().get(value).header("X-AUTOMATED-TOOL", "ccadb").send()?;
        tar::Archive::new(bzip2::bufread::BzDecoder::new(BufReader::new(resp))).unpack(&home)?;
        return Ok(Firefox{ home, executable});
    }
}

impl TryFrom<&str> for Firefox {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        match value.parse::<Url>() {
            Ok(url) => url.try_into(),
            // ParseError is a leaked private? Ugh.
            Err(err) => Err(Error::from(err.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;
    use fs_extra;

//    #[test]
//    fn asdfgsd() {
//        Firefox{ executable: PathBuf::from(r#"/usr/lol/tmp/"#)}.init_profile();
//    }

    #[test]
    fn smoke() {
        let ff: Firefox = (*NIGHTLY).clone().try_into().unwrap();
    }
    
    #[test]
    fn please() {
//        let ff: Firefox = (*NIGHTLY).clone().try_into().unwrap();
////        println!("{}", ff.home.path().to_string_lossy());
////        std::thread::sleep(Duration::from_secs(60*5));
////        fs_extra::dir::copy(ff.home.path(), "/home/chris/ff",  &fs_extra::dir::CopyOptions::new());
//        let profile = ff.create_profile().unwrap();
//        println!("GETTING OUT! {}", profile.home.path().to_string_lossy());
//        std::thread::sleep(Duration::from_secs(60*5));
//        fs_extra::dir::copy(profile.home.path(), "/home/chris/pwease", &fs_extra::dir::CopyOptions::new());
    }
}