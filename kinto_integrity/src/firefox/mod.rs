/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use reqwest::Url;
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

lazy_static! {
    pub static ref NIGHTLY: Url =
        "https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=linux64&lang=en-US"
            .parse()
            .unwrap();
    pub static ref BETA: Url =
        "https://download.mozilla.org/?product=firefox-beta-latest-ssl&os=linux64&lang=en-US"
            .parse()
            .unwrap();
    static ref FIREFOX_NIGHTLY: RwLock<Option<Firefox>> = RwLock::new(None);
    static ref FIREFOX_BETA: RwLock<Option<Firefox>> = RwLock::new(None);
    static ref XVFB: Xvfb = Xvfb::new().unwrap();
}

impl FIREFOX_NIGHTLY {
    const release: Release = Release::Nightly;

    pub fn update_loop(&mut self) {
        loop {
            self.update();
            std::thread::sleep(Duration::from_secs(60 * 60));
        }
    }

    pub fn update(&self) {
        info!("Scheduled {} update triggered.", Self::release);
        match self.write() {
            Ok(mut guard) => match guard.as_mut() {
                Some(ff) => match ff.update() {
                    Ok(_) => (),
                    Err(err) => error!("{}", err),
                },
                None => {
                    let result: Result<Firefox> = Self::release.try_into();
                    match result {
                        Ok(ff) => *guard = Some(ff),
                        Err(err) => error!("{:?}", err),
                    };
                }
            },
            Err(err) => error!("{}", err),
        }
    }
}

impl FIREFOX_BETA {
    const release: Release = Release::Beta;

    pub fn update_loop(&mut self) {
        loop {
            info!("Scheduled {} update triggered.", Self::release);
            match self.write() {
                Ok(mut guard) => match guard.as_mut() {
                    Some(ff) => match ff.update() {
                        Ok(_) => (),
                        Err(err) => error!("{}", err),
                    },
                    None => {
                        let result: Result<Firefox> = Self::release.try_into();
                        match result {
                            Ok(ff) => *guard = Some(ff),
                            Err(err) => error!("{:?}", err),
                        };
                    }
                },
                Err(err) => error!("{}", err),
            }
            std::thread::sleep(Duration::from_secs(60 * 60));
        }
    }
}

pub fn init() {
    let nightly_downloader = || {
        info!("Initializing {}", Release::Nightly);
        let result: Result<Firefox> = Release::Nightly.try_into();
        match result {
            Ok(ff) => match FIREFOX_NIGHTLY.write() {
                Ok(mut guard) => *guard = Some(ff),
                Err(err) => error!("{:?}", err),
            },
            Err(err) => error!("{:?}", err),
        };
    };
    let beta_downloader = || {
        info!("Initializing {}", Release::Beta);
        let result: Result<Firefox> = Release::Beta.try_into();
        match result {
            Ok(ff) => match FIREFOX_BETA.write() {
                Ok(mut guard) => *guard = Some(ff),
                Err(err) => error!("{:?}", err),
            },
            Err(err) => error!("{:?}", err),
        };
    };
    let nightly_handle = std::thread::spawn(nightly_downloader);
    let beta_handle = std::thread::spawn(beta_downloader);
    match nightly_handle.join() {
        Ok(_) => (),
        Err(err) => error!("{:?}", err),
    };
    match beta_handle.join() {
        Ok(_) => (),
        Err(err) => error!("{:?}", err),
    };
    let nightly_updater = move || loop {
        std::thread::sleep(Duration::from_secs(60 * 60));
        info!("Scheduled {} update triggered.", Release::Nightly);
        match FIREFOX_NIGHTLY.write() {
            Ok(mut guard) => {
                match guard.as_mut() {
                    Some(ff) => match ff.update() {
                        Ok(_) => (),
                        Err(err) => error!("{}", err),
                    },
                    None => nightly_downloader(),
                };
            }
            Err(err) => error!("{}", err),
        };
    };
    let beta_updater = move || loop {
        std::thread::sleep(Duration::from_secs(60 * 60));
        info!("Scheduled {} update triggered.", Release::Beta);
        match FIREFOX_BETA.write() {
            Ok(mut guard) => match guard.as_mut() {
                Some(ff) => match ff.update() {
                    Ok(_) => (),
                    Err(err) => error!("{}", err),
                },
                None => beta_downloader(),
            },
            Err(err) => error!("{}", err),
        };
    };
    info!(
        "Starting the X Virtual Frame Buffer on DISPLAY={}",
        xvfb::DISPLAY_PORT
    );
    let _ = *XVFB;
    std::thread::spawn(nightly_updater);
    std::thread::spawn(beta_updater);
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

#[derive(Copy, Clone)]
enum Release {
    Nightly,
    Beta,
}

impl Into<Url> for Release {
    fn into(self) -> Url {
        match self {
            Release::Nightly => NIGHTLY.clone(),
            Release::Beta => BETA.clone(),
        }
    }
}

impl std::fmt::Display for Release {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Release::Beta => f.write_str("Firefox Beta"),
            Release::Nightly => f.write_str("Firefox Nightly"),
        }
    }
}

impl std::fmt::Debug for Release {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Release::Beta => f.write_str("firefox_beta"),
            Release::Nightly => f.write_str("firefox_nightly"),
        }
    }
}

impl Release {
    pub fn update_message(&self) -> String {
        match self {
            Release::Nightly => format!(
                "{} is not properly initialized. Maybe call -X PATCH /update_firefox",
                Release::Nightly
            ),
            Release::Beta => format!(
                "{} is not properly initialized. Maybe call -X PATCH /beta/update_firefox",
                Release::Beta
            ),
        }
    }
}

pub struct Firefox {
    _home: TempDir,
    executable: OsString,
    profile: Profile,
    etag: String,
    release: Release,
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
    fn try_run_mut<T, FN>(
        target: &RwLock<Option<Firefox>>,
        function: FN,
        release: Release,
    ) -> Result<T>
    where
        FN: Fn(&mut Firefox) -> Result<T>,
    {
        match target.write() {
            Ok(mut guard) => function(guard.as_mut().ok_or(release.update_message())?),
            Err(err) => Err(format!("{}", err))?,
        }
    }

    fn try_run<T, FN>(target: &RwLock<Option<Firefox>>, function: FN, release: Release) -> Result<T>
    where
        FN: Fn(&Firefox) -> Result<T>,
    {
        match target.read() {
            Ok(guard) => function(guard.as_ref().ok_or(release.update_message())?),
            Err(err) => Err(format!("{}", err))?,
        }
    }

    pub fn update_firefox_nightly() -> Result<()> {
        Firefox::try_run_mut(&*FIREFOX_NIGHTLY, Firefox::force_update, Release::Nightly)
    }

    pub fn update_firefox_beta() -> Result<()> {
        Firefox::try_run_mut(&*FIREFOX_BETA, Firefox::force_update, Release::Beta)
    }

    pub fn update_cert_storage_nightly() -> Result<()> {
        Firefox::try_run_mut(
            &*FIREFOX_NIGHTLY,
            Firefox::update_cert_storage,
            Release::Nightly,
        )
    }

    pub fn update_cert_storage_beta() -> Result<()> {
        Firefox::try_run_mut(&*FIREFOX_BETA, Firefox::update_cert_storage, Release::Beta)
    }

    pub fn nightly_cert_storage() -> Result<CertStorage> {
        Firefox::try_run(
            &*FIREFOX_NIGHTLY,
            Firefox::get_cert_storage,
            Release::Nightly,
        )
    }

    pub fn beta_cert_storage() -> Result<CertStorage> {
        Firefox::try_run(&*FIREFOX_BETA, Firefox::get_cert_storage, Release::Beta)
    }

    fn get_cert_storage(&self) -> Result<CertStorage> {
        self.profile.cert_storage()
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
            .chain_err(|| "failed to create a profile for Firefox")?;
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
                        "failed to start {} in the context of the profile at {}",
                        self.release, self.profile.home
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
                return Err(format!(
                    "{} timed out by taking more than ten seconds to initialize the profile at {}",
                    self.release, self.profile.home
                )
                .into());
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
                return Err(format!("{} timed out by taking more than ten seconds to begin population cert_storage at {}", self.release, cert_storage_name).into());
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
        let resp = http::new_get_request(self.release.into())
            .header("If-None-Match", self.etag.clone())
            .send()?;
        if resp.status() == 304 {
            info!("{} reported no changes.", self.release);
            return Ok(());
        }
        info!("{} claims an update.", self.release);
        let new_ff = self.release.try_into()?;
        std::mem::replace(self, new_ff);
        Ok(())
    }

    /// Completely ignores the etag header and forces and download of Firefox.
    pub fn force_update(&mut self) -> Result<()> {
        let new_ff = self.release.try_into()?;
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

impl TryFrom<Release> for Firefox {
    type Error = Error;

    fn try_from(release: Release) -> Result<Self> {
        let resp = http::new_get_request(release.into()).send()?;
        let _home = TempDir::new(format!("kinto_integrity_{:?}", release).as_str())?;
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
            release,
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
