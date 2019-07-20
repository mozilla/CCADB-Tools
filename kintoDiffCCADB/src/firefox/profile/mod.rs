use tempdir::TempDir;
use crate::errors::*;
use crate::firefox::Firefox;

const TMP_PREFIX: &str = "kinto_integrity_profile";

pub struct Profile {
    pub name: String,
    pub home: TempDir
}

impl Profile {

    pub fn new() -> Result<Profile> {
        let name = format!("{:x}", rand::random::<u64>());
        let path = TempDir::new(TMP_PREFIX)?;
        Ok(Profile{ name, home: path })
    }
}