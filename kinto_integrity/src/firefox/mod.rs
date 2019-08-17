/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use reqwest::{Response, Url};
use std::convert::{TryFrom, TryInto};

use tempdir::TempDir;

use lazy_static;

use crate::errors::*;
use crate::firefox::profile::Profile;
use std::ffi::OsString;
use std::io::BufReader;
use std::process::{Child, Command, Stdio};
use std::sync::RwLock;
use std::time::Duration;

use crate::firefox::cert_storage::CertStorage;
use crate::http;
use xvfb::Xvfb;

pub mod cert_storage;
pub mod profile;

mod xvfb;

lazy_static! {
    pub static ref NIGHTLY: Url =
        "https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=linux64&lang=en-US"
            .parse()
            .unwrap();
    pub static ref FIREFOX: RwLock<Firefox> = RwLock::new((*NIGHTLY).clone().try_into().unwrap());
    static ref XVFB: Xvfb = Xvfb::new().unwrap();
}

const CREATE_PROFILE: &str = "-CreateProfile";
const WITH_PROFILE: &str = "-profile";
const NULL_DISPLAY_ENV: (&str, &str) = ("DISPLAY", ":99");

const PROFILE_CREATION_TIMEOUT: u64 = 10; // seconds
const CERT_STORAGE_POPULATION_TIMEOUT: u64 = 30; // seconds
                                                 // Once cert_storage is created we make note of its original size.
                                                 // The moment we notice that the size of the file has increased we
                                                 // assume that population of the database has begun. This heuristic
                                                 // is the idea that if we have seen that file has STOPPED increasing in
                                                 // size for ten ticks of the algorithm, then it is likely completely populated.
                                                 //
                                                 // Note that, of course, this is only a heuristic. Meaning that if we improperly move on
                                                 // without getting the full database, that firefox::cert_storage parsing is likely to fail.
const CERT_STORAGE_POPULATION_HEURISTIC: u64 = 10; // ticks

pub fn init() {
    info!(
        "Starting the X Virtual Frame Buffer on DISPLAY={}",
        xvfb::DISPLAY_PORT
    );
    let _ = *XVFB;
    info!("Initializing Firefox Nightly");
    let _ = *FIREFOX;
    info!("Starting the Firefox Nightly updater thread");
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(60 * 60));
        info!("Scheduled Firefox update triggered.");
        match FIREFOX.write() {
            Ok(mut ff) => match ff.update() {
                Ok(_) => (),
                Err(err) => error!("{:?}", err),
            },
            Err(err) => error!("{:?}", err),
        }
    });
}

/// std::process::Child does not implement drop in a meaningful way.
/// In our use case we just want to kill the process.
struct DroppableChild {
    child: Child,
}

impl Drop for DroppableChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

pub struct Firefox {
    _home: TempDir,
    executable: OsString,
    profile: Profile,
    etag: String,
}

impl Drop for Firefox {
    fn drop(&mut self) {
        info!(
            "Deleting Firefox located at {}",
            self._home.path().to_string_lossy()
        );
    }
}

impl Firefox {
    pub fn default() -> Result<CertStorage> {
        match FIREFOX.read() {
            Err(err) => Err(format!("{:?}", err))?,
            Ok(ff) => ff
                .profile
                .cert_storage()
                .chain_err(|| "failed to parse cert_storage"),
        }
    }

    /// Creates and initializes a new profile managed by this instance of Firefox.
    ///
    /// Note that profile creation entails the spinning of a file watcher for cert_storage.
    /// We receive no explicit declaration of cert_storage initalization from Firefox, so
    /// we have to simply watch the file and wait for it to stop growing in size.
    fn create_profile(&self) -> Result<()> {
        // Register the profile with Firefox.
        info!(
            "Creating profile {} at {}",
            self.profile.name, self.profile.home
        );
        self.cmd()
            .args(self.create_profile_args())
            .output()
            .chain_err(|| "failed to create a profile for Firefox Nightly")?;
        // Startup Firefox with the given profile. Doing so will initialize the entire
        // profile to a fresh state and begin populating the cert_storage database.
        info!(
            "Initializing profile {} at {}",
            self.profile.name, self.profile.home
        );
        let _cmd = DroppableChild {
            child: self
                .cmd()
                .args(self.init_profile_args())
                .spawn()
                .chain_err(|| {
                    format!(
                        "failed to start Firefox Nightly in the context of the profile at {}",
                        self.profile.home
                    )
                })?,
        };
        // Unfortunately, it's not like Firefox is giving us update progress over stdout,
        // so in order to be notified if cert storage is done being populate we gotta
        // listen in on the file and check up on its size.
        let database = || std::fs::metadata(self.profile.cert_storage_path());
        // Spin until it's created.
        let cert_storage_name = self
            .profile
            .cert_storage_path()
            .to_string_lossy()
            .into_owned();
        info!("Waiting for {} to be created.", cert_storage_name);
        let mut initial_size;
        let start = std::time::Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(100));
            if start.elapsed() == Duration::from_secs(PROFILE_CREATION_TIMEOUT) {
                return Err(format!("Firefox Nightly timed out by taking more than ten seconds to initialize the profile at {}", self.profile.home).into());
            }
            match database() {
                Err(_) => (),
                Ok(db) => {
                    initial_size = db.len();
                    break;
                }
            }
        }
        let start = std::time::Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(100));
            if start.elapsed() == Duration::from_secs(CERT_STORAGE_POPULATION_TIMEOUT) {
                return Err(format!("Firefox Nightly timed out by taking more than ten seconds to begin population cert_storage at {}", cert_storage_name).into());
            }
            let size = database()?.len();
            if size != initial_size {
                initial_size = size;
                break;
            }
        }
        info!("{} created", cert_storage_name);
        // Spin until we are reasonably sure that it is populated.
        // This is only a heuristic and is not necessarily correct.
        info!("Watching {} to be populated", cert_storage_name);
        let mut size = initial_size;
        let mut counter = 0;
        loop {
            let current_size = database()?.len();
            if current_size == size {
                counter += 1;
            } else {
                size = current_size;
                counter = 0;
            }
            if counter >= CERT_STORAGE_POPULATION_HEURISTIC {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Ok(())
    }

    /// Attempts to consume this instance of Firefox and replace it with a possible update.
    ///
    /// Under the condition that no change has been made on the remote, then this method
    /// returns self.
    pub fn update(&mut self) -> Result<()> {
        let resp = http::new_get_request(NIGHTLY.clone())
            .header("If-None-Match", self.etag.clone())
            .send()?;
        if resp.status() == 304 {
            info!("{} reported no changes to Firefox", NIGHTLY.clone());
            return Ok(());
        }
        info!("{} claims an update to Firefox", NIGHTLY.clone());
        let new_ff = resp.try_into()?;
        std::mem::replace(self, new_ff);
        Ok(())
    }

    /// Completely ignores the etag header and forces and download of Firefox.
    pub fn force_update(&mut self) -> Result<()> {
        let resp = http::new_get_request(NIGHTLY.clone()).send()?;
        let new_ff = resp.try_into()?;
        std::mem::replace(self, new_ff);
        Ok(())
    }

    /// Creates a new profile with a freshly populated cert_storage.
    pub fn update_cert_storage(&mut self) -> Result<()> {
        self.profile = Profile::new()?;
        self.create_profile()
    }

    /// Generates the arguments to fulfill:
    ///     ./firefox -CreateProfile "profile_name profile_dir"
    /// See https://developer.mozilla.org/en-US/docs/Mozilla/Command_Line_Options#-CreateProfile_.22profile_name_profile_dir.22
    fn create_profile_args(&self) -> Vec<String> {
        vec![
            CREATE_PROFILE.to_string(),
            format!(r#"{} {}"#, self.profile.name, self.profile.home),
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
    fn init_profile_args(&self) -> Vec<String> {
        vec![WITH_PROFILE.to_string(), self.profile.home.clone()]
    }

    /// Returns a Command which is partially pre-built with the more fiddly bits of
    /// starting a headlesss Firefox. E.G. predeclaring the DISPLAY environment variable.
    fn cmd(&self) -> Command {
        let mut cmd = Command::new(&self.executable);
        cmd.env(NULL_DISPLAY_ENV.0, NULL_DISPLAY_ENV.1);
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        cmd
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

/// Creates a Firefox instance from the given Url.
impl TryFrom<Url> for Firefox {
    type Error = Error;

    fn try_from(value: Url) -> Result<Self> {
        http::new_get_request(value).send()?.try_into()
    }
}

/// Response is expected to be a stream of tar.bzip archive of Firefox.
impl TryFrom<Response> for Firefox {
    type Error = Error;

    fn try_from(resp: Response) -> Result<Self> {
        let _home = TempDir::new("kinto_integrity_firefox_nightly")?;
        let executable = _home
            .path()
            .join("firefox")
            .join("firefox")
            .into_os_string();
        let etag = resp
            .headers()
            .get("etag")
            .chain_err(|| format!("No etag header was present in a request to {}", resp.url()))?
            .to_str()
            .chain_err(|| format!("The etag header from {} could not be parsed", resp.url()))?
            .to_string();
        info!("Expanding to {}", _home.as_ref().to_string_lossy());
        let content_length = resp
            .content_length()
            .chain_err(|| format!("Could not get a content length from {}", resp.url()))?;
        let bar = indicatif::ProgressBar::new(content_length);
        tar::Archive::new(bzip2::bufread::BzDecoder::new(BufReader::new(
            bar.wrap_read(resp),
        )))
        .unpack(&_home)?;
        let profile = Profile::new()?;
        let ff = Firefox {
            _home,
            executable,
            profile,
            etag,
        };
        ff.create_profile()?;
        Ok(ff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn smoke() {
        let _: Firefox = (*NIGHTLY).clone().try_into().unwrap();
    }
}
