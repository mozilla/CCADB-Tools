use tempdir::TempDir;
use crate::errors::*;
use crate::firefox::Firefox;
use std::ffi::{OsString, OsStr};
use std::path::{Path, PathBuf};

const TMP_PREFIX: &str = "kinto_integrity_profile";
const CERT_STORAGE_DIR: &str = "security_state";
const CERT_STORAGE_DB: &str = "data.mdb";

pub struct Profile {
    pub name: String,
    pub home: String,
    tmp: TempDir
}

impl Profile {

    pub fn new() -> Result<Profile> {
        let name = format!("{:x}", rand::random::<u64>());
        let tmp = TempDir::new(TMP_PREFIX)?;
        let home = match tmp.as_ref().to_str() {
            Some(string) => string.to_string(),
            None => Err(Error::from("failed get the &str representation of a temp directory created for a profile"))?
        };
        Ok(Profile{ name, home, tmp })
    }

    pub fn cert_storage(&self) -> PathBuf {
        Path::new(&self.home).join(CERT_STORAGE_DIR).join(CERT_STORAGE_DB)
    }
}