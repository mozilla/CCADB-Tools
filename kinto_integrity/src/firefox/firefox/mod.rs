/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::errors::*;
use crate::firefox::cert_storage::CertStorage;
use crate::firefox::profile::Profile;
use crate::http;
use reqwest::Url;
use std::convert::TryFrom;
use std::ffi::OsString;
use std::io::BufReader;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempdir::TempDir;

const CREATE_PROFILE: &str = "-CreateProfile";
const WITH_PROFILE: &str = "-profile";
const NULL_DISPLAY_ENV: (&str, &str) = ("DISPLAY", ":99");

const CERT_STORAGE_CREATION_TIMEOUT: u64 = 60 * 30; // 30 minutes
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
    static ref FF_LOCK: std::sync::Mutex<bool> = std::sync::Mutex::default();
}

/// std::process::Child does not implement drop in a meaningful way.
/// In our use case we just want to kill the process.
pub struct DroppableChild {
    pub(crate) child: Child,
}

impl Drop for DroppableChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

#[derive(Default)]
pub struct Firefox {
    home: Option<TempDir>,
    profile: Option<Profile>,
    executable: OsString,
    etag: String,
}

impl Drop for Firefox {
    fn drop(&mut self) {
        match &self.home {
            Some(tmp) => info!(
                "Deleting Firefox located at {}",
                tmp.path().to_string_lossy()
            ),
            None => (),
        }
    }
}

impl Firefox {
    pub fn get_profile(&self) -> IntegrityResult<&Profile> {
        match self.profile.as_ref() {
            Some(profile) => Ok(profile),
            None => Err(IntegrityError::new(PROFILE_NOT_INITIALIZED)),
        }
    }

    pub fn cert_storage(&self) -> IntegrityResult<CertStorage> {
        self.get_profile()?.cert_storage()
    }

    /// Creates and initializes a new profile managed by this instance of Firefox.
    ///
    /// Note that profile creation entails the spinning of a file watcher for cert_storage.
    /// We receive no explicit declaration of cert_storage initalization from Firefox, so
    /// we have to simply watch the file and wait for it to stop growing in size.
    fn create_profile(&self) -> IntegrityResult<()> {
        let profile = self.get_profile()?;
        // Register the profile with Firefox.
        info!("Creating profile {} at {}", profile.name, profile.home);
        self.cmd()
            .args(self.create_profile_args())
            .output()
            .map_err(|err| {
                IntegrityError::new(PROFILE_INIT_ERR)
                    .with_err(err)
                    .with_context(ctx!(
                        ("profile_name", &profile.name),
                        ("profile_home", &profile.home)
                    ))
            })?;
        // Startup Firefox with the given profile. Doing so will initialize the entire
        // profile to a fresh state and begin populating the cert_storage database.
        info!("Initializing profile {} at {}", profile.name, profile.home);
        let _cmd = DroppableChild {
            child: self
                .cmd()
                .args(self.init_profile_args())
                .spawn()
                .map_err(|err| {
                    IntegrityError::new(FIREFOX_START_ERR)
                        .with_err(err)
                        .with_context(ctx!(("invocation", self.init_profile_args().join(" "))))
                })?,
        };
        // Unfortunately, it's not like Firefox is giving us update progress over stdout,
        // so in order to be notified if cert storage is done being populate we gotta
        // listen in on the file and check up on its size.
        let database = || {
            std::fs::metadata(profile.cert_storage_path()).map_err(|err| {
                IntegrityError::new(CERT_STORAGE_DELETED)
                    .with_err(err)
                    .with_context(ctx!((
                        "path",
                        profile.cert_storage_path().to_str().unwrap_or("unknown")
                    )))
            })
        };
        // Spin until it's created.
        let cert_storage_name = profile.cert_storage_path().to_string_lossy().into_owned();
        info!("Waiting for {} to be created.", cert_storage_name);
        let mut initial_size;
        let start = std::time::Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(100));
            match database() {
                Err(_) => (),
                Ok(db) => {
                    initial_size = db.len();
                    break;
                }
            }
            if std::time::Instant::now().duration_since(start).as_secs()
                >= CERT_STORAGE_CREATION_TIMEOUT
            {
                return Err(IntegrityError::new(format!(
                    "Firefox took longer that {} minutes to create a cert_storage file",
                    CERT_STORAGE_CREATION_TIMEOUT / 60
                )));
            }
        }
        let start = std::time::Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(100));
            let size = database()?.len();
            if size != initial_size {
                initial_size = size;
                break;
            }
            if std::time::Instant::now().duration_since(start).as_secs()
                >= CERT_STORAGE_CREATION_TIMEOUT
            {
                return Err(IntegrityError::new(format!(
                    "Firefox took longer that {} minutes to begin populating cert_storage",
                    CERT_STORAGE_CREATION_TIMEOUT / 60
                )));
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

    pub fn update(&mut self, url: Url) -> IntegrityResult<Option<()>> {
        let _lock = match FF_LOCK.lock() {
            Ok(lock) => lock,
            Err(err) => return Err(IntegrityError::new(POISONED_LOCK).with_err(err)),
        };
        let url_str = url.as_str().to_string();
        let resp = http::new_get_request(url)
            .header("If-None-Match", self.etag.clone())
            .send()
            .map_err(|err| {
                IntegrityError::new(FIREFOX_DOWNLOAD_ERR)
                    .with_err(err)
                    .with_context(ctx!(("url", &url_str)))
            })?;
        if resp.status() == 304 {
            return Ok(None);
        }
        let _ = std::mem::replace(self, Self::try_from(resp)?);
        Ok(Some(()))
    }

    pub fn force_update(&mut self, url: Url) -> IntegrityResult<()> {
        let _lock = match FF_LOCK.lock() {
            Ok(lock) => lock,
            Err(err) => return Err(IntegrityError::new(POISONED_LOCK).with_err(err)),
        };
        let url_str = url.as_str().to_string();
        let resp = http::new_get_request(url)
            .header("If-None-Match", self.etag.clone())
            .send()
            .map_err(|err| {
                IntegrityError::new(FIREFOX_DOWNLOAD_ERR)
                    .with_err(err)
                    .with_context(ctx!(("url", &url_str)))
            })?;
        std::mem::replace(self, Self::try_from(resp)?);
        Ok(())
    }

    pub fn update_cert_storage(&mut self) -> IntegrityResult<()> {
        let _lock = match FF_LOCK.lock() {
            Ok(lock) => lock,
            Err(err) => return Err(IntegrityError::new(POISONED_LOCK).with_err(err)),
        };
        self.profile = Some(Profile::new()?);
        self.create_profile()
    }

    /// Generates the arguments to fulfill:
    ///     ./firefox -CreateProfile "profile_name profile_dir"
    /// See https://developer.mozilla.org/en-US/docs/Mozilla/Command_Line_Options#-CreateProfile_.22profile_name_profile_dir.22
    fn create_profile_args(&self) -> Vec<String> {
        vec![
            CREATE_PROFILE.to_string(),
            format!(
                r#"{} {}"#,
                self.profile.as_ref().unwrap().name,
                self.profile.as_ref().unwrap().home
            ),
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
        vec![
            WITH_PROFILE.to_string(),
            self.profile.as_ref().unwrap().home.clone(),
        ]
    }

    /// Returns a Command which is partially pre-built with the more fiddly bits of
    /// starting a headlesss Firefox. E.G. predeclaring the DISPLAY environment variable.
    fn cmd(&self) -> Command {
        let mut cmd = Command::new(&self.executable);
        cmd.env(NULL_DISPLAY_ENV.0, NULL_DISPLAY_ENV.1);
        cmd.stderr(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd
    }
}

impl TryFrom<reqwest::blocking::Response> for Firefox {
    type Error = IntegrityError;

    fn try_from(resp: reqwest::blocking::Response) -> IntegrityResult<Self> {
        let url = resp.url().to_string();
        let home = TempDir::new("kinto_integrity")
            .map_err(|err| IntegrityError::new(FIREFOX_TEMP_DIR_ERR).with_err(err))?;
        let executable = home.path().join("firefox").join("firefox").into_os_string();
        let etag = resp
            .headers()
            .get("etag")
            .ok_or(IntegrityError::new(ETAG_PRESENCE_ERR).with_context(ctx!(("url", &url))))?
            .to_str()
            .map_err(|err| {
                IntegrityError::new(ETAG_PARSE_ERR)
                    .with_err(err)
                    .with_context(ctx!(("url", &url)))
            })?
            .to_string();
        info!("Expanding to {}", home.as_ref().to_string_lossy());
        let content_length = resp.content_length().ok_or(
            IntegrityError::new(NO_CONTENT_LENGTH_ERR)
                .with_context(ctx!(("downloaded_from", &url))),
        )?;
        let bar = indicatif::ProgressBar::new(content_length);
        tar::Archive::new(bzip2::bufread::BzDecoder::new(BufReader::new(
            bar.wrap_read(resp),
        )))
        .unpack(&home)
        .map_err(|err| {
            IntegrityError::new(BZIP_EXTRACT_ERR)
                .with_err(err)
                .with_context(ctx!(("downloaded_from", &url)))
        })?;
        let profile = Profile::new()?;
        let ff = Firefox {
            home: Some(home),
            executable,
            profile: Some(profile),
            etag,
        };
        ff.create_profile()?;
        Ok(ff)
    }
}

const PROFILE_NOT_INITIALIZED: &str = "Firefox has not yet initialized a working profile with a \
populated cert_storage. Please try again in 7-15 minutes.";
const PROFILE_INIT_ERR: &str = "We run Firefox in the context of a shared profile that is stored \
in a temporary directory, however Firefox has appeared to fail to initialize that profile.";
const FIREFOX_START_ERR: &str = "We run Firefox as a plain subprocess and point to an \
Xvfb instance to fake graphical output. However, it appears as though Firefox failed to \
start entirely.";
const CERT_STORAGE_DELETED: &str = "We saw that the cert_storage file was created, but then it \
appeared to have been deleted in mid polling.";
const FIREFOX_DOWNLOAD_ERR: &str = "We failed to connect and download a copy of Firefox.";
const POISONED_LOCK: &str = "The mutex for locking access to the Firefox binary appears to \
be poisoned. This implies that perhaps a crash occurred in another thread while it held a lock. \
As this will occur for all future accesses to the lock, The best remediation for this issue is to s\
imply restart the application and attempt to debug the original crash.";
const FIREFOX_TEMP_DIR_ERR: &str =
    "We failed to allocate new temporary storage for a download of Firefox.";
const ETAG_PRESENCE_ERR: &str =
    "We use an etag to know whether or not an update to Firefox has been \
issued, however no etag was present on the response.";
const ETAG_PARSE_ERR: &str = "We use an etag to know whether or not an update to Firefox has been \
issued. We received and etag, but it could not parse to a UTF-8 string.";
const NO_CONTENT_LENGTH_ERR: &str = "Our Firefox download did not have a Content-Length header.";
const BZIP_EXTRACT_ERR: &str = "We expect Firefox to be bundled in a tar.bzip file, however \
we were unsuccessful in extracting such an archive.";
