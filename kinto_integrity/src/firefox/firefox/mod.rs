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

const PROFILE_CREATION_TIMEOUT: u64 = 60; // seconds
const CERT_STORAGE_POPULATION_TIMEOUT: u64 = 60; // seconds
                                                 // Once cert_storage is created we make note of its original size.
                                                 // The moment we notice that the size of the file has increased we
                                                 // assume that population of the database has begun. This heuristic
                                                 // is the idea that if we have seen that file has STOPPED increasing in
                                                 // size for ten ticks of the algorithm, then it is likely completely populated.
                                                 //
                                                 // Note that, of course, this is only a heuristic. Meaning that if we improperly move on
                                                 // without getting the full database, that firefox::cert_storage parsing is likely to fail.
const CERT_STORAGE_POPULATION_HEURISTIC: u64 = 10; // ticks

lazy_static!(
    static ref FF_LOCK: std::sync::Mutex<bool> = std::sync::Mutex::default();
);

/// std::process::Child does not implement drop in a meaningful way.
/// In our use case we just want to kill the process.
struct DroppableChild {
    child: Child,
}

impl Drop for DroppableChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = Command::new("wait").output();
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
    pub fn cert_storage(&self) -> Result<CertStorage> {
        self.profile
            .as_ref()
            .ok_or("not initalized")?
            .cert_storage()
    }

    /// Creates and initializes a new profile managed by this instance of Firefox.
    ///
    /// Note that profile creation entails the spinning of a file watcher for cert_storage.
    /// We receive no explicit declaration of cert_storage initalization from Firefox, so
    /// we have to simply watch the file and wait for it to stop growing in size.
    fn create_profile(&self) -> Result<()> {
        let profile = self.profile.as_ref().ok_or("not initialized")?;
        // Register the profile with Firefox.
        info!("Creating profile {} at {}", profile.name, profile.home);
        self.cmd()
            .args(self.create_profile_args())
            .output()
            .chain_err(|| "failed to create a profile for Firefox")?;
        // Startup Firefox with the given profile. Doing so will initialize the entire
        // profile to a fresh state and begin populating the cert_storage database.
        info!("Initializing profile {} at {}", profile.name, profile.home);
        let _cmd = DroppableChild {
            child: self
                .cmd()
                .args(self.init_profile_args())
                .spawn()
                .chain_err(|| {
                    format!(
                        "failed to start Firefox in the context of the profile at {}",
                        profile.home
                    )
                })?,
        };
        // Unfortunately, it's not like Firefox is giving us update progress over stdout,
        // so in order to be notified if cert storage is done being populate we gotta
        // listen in on the file and check up on its size.
        let database = || std::fs::metadata(profile.cert_storage_path());
        // Spin until it's created.
        let cert_storage_name = profile.cert_storage_path().to_string_lossy().into_owned();
        info!("Waiting for {} to be created.", cert_storage_name);
        let mut initial_size;
        let start = std::time::Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(100));
            if start.elapsed() >= Duration::from_secs(PROFILE_CREATION_TIMEOUT) {
                return Err(format!(
                        "Firefox timed out by taking more than {} seconds to initialize the profile at {}",
                        PROFILE_CREATION_TIMEOUT,
                        profile.home
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
            if start.elapsed() >= Duration::from_secs(CERT_STORAGE_POPULATION_TIMEOUT) {
                return Err(format!("Firefox timed out by taking more than {} seconds to begin population cert_storage at {}", CERT_STORAGE_POPULATION_TIMEOUT, cert_storage_name).into());
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

    pub fn update(&mut self, url: Url) -> Result<Option<()>> {
        let _lock = match FF_LOCK.lock() {
            Ok(lock) => lock,
            Err(err) => return Err(Error::from(err.to_string()))
        };
        let resp = http::new_get_request(url)
            .header("If-None-Match", self.etag.clone())
            .send()
            .chain_err(|| "")?;
        if resp.status() == 304 {
            return Ok(None);
        }
        std::mem::replace(self, Self::try_from(resp)?);
        Ok(Some(()))
    }

    pub fn force_update(&mut self, url: Url) -> Result<()> {
        let _lock = match FF_LOCK.lock() {
            Ok(lock) => lock,
            Err(err) => return Err(Error::from(err.to_string()))
        };
        let resp = http::new_get_request(url)
            .header("If-None-Match", self.etag.clone())
            .send()
            .chain_err(|| "")?;
        std::mem::replace(self, Self::try_from(resp)?);
        Ok(())
    }

    pub fn update_cert_storage(&mut self) -> Result<()> {
        let _lock = match FF_LOCK.lock() {
            Ok(lock) => lock,
            Err(err) => return Err(Error::from(err.to_string()))
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
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        cmd
    }
}

impl TryFrom<reqwest::blocking::Response> for Firefox {
    type Error = Error;

    fn try_from(resp: reqwest::blocking::Response) -> Result<Self> {
        let home = TempDir::new("kinto_integrity").chain_err(|| "")?;
        let executable = home.path().join("firefox").join("firefox").into_os_string();
        let etag = resp
            .headers()
            .get("etag")
            .chain_err(|| format!("No etag header was present in a request to {}", resp.url()))?
            .to_str()
            .chain_err(|| format!("The etag header from {} could not be parsed", resp.url()))?
            .to_string();
        info!("Expanding to {}", home.as_ref().to_string_lossy());
        let content_length = resp
            .content_length()
            .chain_err(|| format!("Could not get a content length from {}", resp.url()))?;
        let bar = indicatif::ProgressBar::new(content_length);
        tar::Archive::new(bzip2::bufread::BzDecoder::new(BufReader::new(
            bar.wrap_read(resp),
        )))
        .unpack(&home)
        .chain_err(|| "")?;
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
