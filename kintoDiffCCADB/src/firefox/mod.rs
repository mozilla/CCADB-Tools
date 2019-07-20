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

mod profile;

lazy_static!(
    pub static ref NIGHTLY: Url = "https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=linux64&lang=en-US".parse().unwrap();
    pub static ref FIREFOX: Mutex<Firefox> = Mutex::new((*NIGHTLY).clone().try_into().unwrap());
);

pub struct Firefox {
    home: TempDir,
    executable: PathBuf
}

impl Firefox {

//    pub fn init_profile(&self) -> TempDir {
//        let profile  = tempdir::TempDir::new("kinto_diff_ccadb").unwrap();
//        let executable = self.executable.join("firefox").to_string_lossy();
//        let profile_name = format!("{:x}", rand::random:<u32>:());
//        let profile_location = profile.path().to_string_lossy();
//        let cmd  = format!(
//            r#"{} -CreateProfile "{:x} {}""#,
//            executable, profile_name, profile_location);
//        println!("{}", cmd);
//        Command::new(cmd).env("DISPLAY", ":99").spawn().unwrap();
//        let cmd = format!("{} -P {}", executable, profile_name);
//        Command::new(cmd).env("DISPLAY", ":99").spawn().
//        profile
//    }

    pub fn create_profile(&self) -> Result<Profile> {
        let profile = Profile::new()?;
        let create_profile_cmd  = format!(
            r#"{} -CreateProfile "{} {}""#,
            self.executable.to_string_lossy(), profile.name, profile.home.path().to_string_lossy());
        Command::new(create_profile_cmd).env("DISPLAY", ":99").output().unwrap();
        let profile_init_command = format!(r#"{} -profile {}"#, self.executable.to_string_lossy(), profile.home.path().to_string_lossy());
        let mut cmd = Command::new(profile_init_command).spawn().unwrap();
        let database = || {
             std::fs::metadata(profile.home.path().join("security_state").join("data.mdb"))
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
                    if counter >= 6 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
        // Child does not implement drop in a meaningful way, so
        // we must be careful to not return early without first
        // cleaning it up.
        cmd.kill();
        match error {
            None => Ok(profile),
            Some(err) => err
        }
    }

//    pub fn run(cmd: &str) -> Result<Child> {
//        Command::new(cmd).env("DISPLAY", ":99").spawn()
//    }

    pub fn from_nightly() -> Result<Firefox> {
        (*NIGHTLY).clone().try_into()
    }
}

impl TryFrom<Url> for Firefox {
    type Error = Error;

    fn try_from(value: Url) -> Result<Self> {
        let home = TempDir::new("")?;
        let executable = home.path().join("firefox").join("firefox");
        let resp = Client::new().get(value).header("X-AUTOMATED-TOOL", "ccadb").send()?;
        tar::Archive::new(bzip2::bufread::BzDecoder::new(BufReader::new(resp))).unpack(&home)?;
        return Ok(Firefox{ home, executable});
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
        let ff: Firefox = (*NIGHTLY).clone().try_into().unwrap();
        ff.create_profile().unwrap();
    }
}