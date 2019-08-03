use reqwest::Client;
use reqwest::Url;
use std::convert::{TryFrom, TryInto};

use tempdir::TempDir;

use lazy_static;

use crate::errors::*;
use crate::firefox::profile::Profile;
use crate::{USER_AGENT, X_AUTOMATED_TOOL};
use std::ffi::OsString;
use std::io::BufReader;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

pub mod profile;

lazy_static! {
    pub static ref NIGHTLY: Url =
        "https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=linux64&lang=en-US"
            .parse()
            .unwrap();
    pub static ref FIREFOX: Mutex<Firefox> = Mutex::new((*NIGHTLY).clone().try_into().unwrap());
}

const CREATE_PROFILE: &str = "-CreateProfile";
const WITH_PROFILE: &str = "-profile";
const NULL_DISPLAY_ENV: (&str, &str) = ("DISPLAY", ":99");

pub struct Firefox {
    home: TempDir,
    executable: OsString,
    pub etag: String,
}

impl Firefox {
    /// Creates and initializes a new profile managed by this instance of Firefox.
    ///
    /// Note that profile creation entails the spinning of a file watcher for cert_storage.
    /// We receive no explicit declaration of cert_storage initalization from Firefox, so
    /// we have to simply watch the file and wait for it to stop growing in size.
    pub fn create_profile(&self) -> Result<Profile> {
        // Creates a name and system tmp directory for our profile.
        let profile = Profile::new()?;
        // Register the profile with Firefox.
        println!("Creating profile {} at {}", profile.name, profile.home);
        self.cmd()
            .args(Firefox::create_profile_args(&profile))
            .output()
            .chain_err(|| "balls")?;
        // Startup Firefox with the given profile. Doing so will initialize the entire
        // profile to a fresh state and begin populating the cert_storage database.
        println!("Initializing profile {} at {}", profile.name, profile.home);
        let mut cmd = self
            .cmd()
            .args(Firefox::init_profile_args(&profile))
            .spawn()
            .chain_err(|| "dang")?;
        // Unfortunately, it's not like Firefox is giving us update progress over stdout,
        // so in order to be notified if cert storage is done being populate we gotta
        // listen in on the file and check up on its size.
        let database = || std::fs::metadata(profile.cert_storage());
        // Spin until it's created.
        let cert_storage_name = profile.cert_storage().to_string_lossy().into_owned();
        println!("Waiting for {} to be created.", cert_storage_name);
        let mut initial_size;
        loop {
            std::thread::sleep(Duration::from_millis(500));
            match database() {
                Err(_) => (),
                Ok(db) => {
                    initial_size = db.len();
                    break;
                }
            }
        }
        loop {
            std::thread::sleep(Duration::from_millis(500));
            match database() {
                Err(_) => panic!("asdasd"),
                Ok(db) => {
                    if db.len() != initial_size {
                        initial_size = db.len();
                        break;
                    }
                }
            }
        }
        println!("{} created", cert_storage_name);
        // Spin until we are reasonably sure that it is populated.
        // This is only a heuristic and is not necessarily correct.
        println!("Watching {} to be populated", cert_storage_name);
        let mut size = initial_size;
        let mut counter = 0;
        let mut error = None;
        loop {
            match database() {
                Err(err) => {
                    eprintln!(
                        "Received an error while stating {}, {}",
                        cert_storage_name, err
                    );
                    error = Some(Err(Error::from(err)));
                    break;
                }
                Ok(db) => {
                    let current = db.len();
                    if current == size {
                        println!("counter is {}", counter);
                        println!("size is {}", current);
                        counter += 1;
                    } else {
                        size = current;
                        counter = 0;
                    }
                    if counter >= 10 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
        // Child does not implement drop in a meaningful way, so
        // we must be careful to not return early without first
        // cleaning it up.
        let _ = cmd.kill();
        match error {
            None => Ok(profile),
            Some(err) => err,
        }
    }

    /// Attempts to consume this instance of Firefox and replace it with a possible update.
    ///
    /// Under the condition that no change has been made on the remote, then this method
    /// returns self.
    pub fn update(&mut self) -> Result<&mut Firefox> {
        let resp = Client::new()
            .get(NIGHTLY.clone())
            .header("X-AUTOMATED-TOOL", "ccadb")
            .header("If-None-Match", self.etag.clone())
            .send()?;
        if resp.status() == 304 {
            println!("{} reported no changes to Firefox", NIGHTLY.clone());
            return Ok(self);
        }
        println!("{} claims an update to Firefox", NIGHTLY.clone());
        let home = TempDir::new("kinto_integrity_firefox_nightly")?;
        let executable = home.path().join("firefox").join("firefox").into_os_string();
        let etag = match resp.headers().get("etag") {
            Some(etag) => match etag.to_str() {
                Ok(string) => string.to_string(),
                Err(err) => return Err(Error::from(err.to_string())),
            },
            None => {
                return Err(Error::from(format!(
                    "no etag header was present in a request to {}",
                    *NIGHTLY
                )))
            }
        };
        tar::Archive::new(bzip2::bufread::BzDecoder::new(BufReader::new(resp))).unpack(&home)?;
        self.home = home;
        self.executable = executable;
        self.etag = etag;
        Ok(self)
    }

    /// Generates the arguments to fulfill:
    ///     ./firefox -CreateProfile "profile_name profile_dir"
    /// See https://developer.mozilla.org/en-US/docs/Mozilla/Command_Line_Options#-CreateProfile_.22profile_name_profile_dir.22
    fn create_profile_args(profile: &Profile) -> Vec<String> {
        vec![
            CREATE_PROFILE.to_string(),
            format!(r#"{} {}"#, profile.name, profile.home),
        ]
    }

    /// Generates the arguments to start Firefox with a particular profile.
    /// Doing so additionally initializes the profile if it has not already been
    /// initialized.
    ///
    /// Note that initialization of cert_storage takes MUCH longer as it is reaching out
    /// to Kinto. The result being that you can startup, and initialize, the profile but
    /// you have to wait around and watch the profile for changes to see if cert_storage
    /// is finished populating.
    fn init_profile_args(profile: &Profile) -> Vec<String> {
        vec![WITH_PROFILE.to_string(), profile.home.clone()]
    }

    /// Returns a Command which is partially pre-built with the more fiddly bits of
    /// starting a headlesss Firefox. E.G. predeclaring the DISPLAY environment variable.
    fn cmd(&self) -> Command {
        let mut cmd = Command::new(&self.executable);
        cmd.env(NULL_DISPLAY_ENV.0, NULL_DISPLAY_ENV.1);
        cmd.stdout(Stdio::null());
        cmd
    }
}

impl TryFrom<Url> for Firefox {
    type Error = Error;

    fn try_from(value: Url) -> Result<Self> {
        println!("Downloading {}", value);
        let home = TempDir::new("")?;
        let executable = home.path().join("firefox").join("firefox").into_os_string();
        let resp = Client::new()
            .get(value)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header("X-AUTOMATED-TOOL", X_AUTOMATED_TOOL)
            .send()?;
        let etag = resp
            .headers()
            .get("etag").chain_err(|| "dang")?
            .to_str().chain_err(|| "dang")?
            .to_string();
        println!("Expanding to {}", home.as_ref().to_string_lossy());
        let content_length = resp.content_length().chain_err(|| "dang")?;
        let bar = indicatif::ProgressBar::new(content_length);
        tar::Archive::new(bzip2::bufread::BzDecoder::new(BufReader::new(
            bar.wrap_read(resp),
        )))
        .unpack(&home)?;
        return Ok(Firefox {
            home,
            executable,
            etag,
        });
    }
}

/// Attempts to parse the given str into a Url and then defers to TryFrom<Url> for Firefox
impl TryFrom<&str> for Firefox {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        match value.parse::<Url>() {
            Ok(url) => url.try_into(),
            Err(err) => Err(Error::from(err.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn asgfdfa() {
        let resp = Client::new()
            .get(NIGHTLY.clone())
            .header("X-AUTOMATED-TOOL", "ccadb")
            .header("If-None-Match", r#""835285c5ea08d3381874b58e4cc54b02""#)
            .send()
            .unwrap();
        println!("{}", resp.status());
        println!("{:?}", resp.headers());
    }

    #[test]
    fn smoke() {
        let _: Firefox = (*NIGHTLY).clone().try_into().unwrap();
    }

    #[test]
    fn asdfdgsdfsdf() {
        println!("{}", *NIGHTLY);
    }

}
