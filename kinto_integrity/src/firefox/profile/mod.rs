/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::errors::*;
use crate::firefox::cert_storage::CertStorage;
use std::convert::TryInto;
use std::path::{Path, PathBuf};
use tempdir::TempDir;

const TMP_PREFIX: &str = "kinto_integrity_profile";
const CERT_STORAGE_DIR: &str = "security_state";
const CERT_STORAGE_DB: &str = "data.mdb";

pub struct Profile {
    pub name: String,
    pub home: String,
    _tmp: TempDir,
}

impl Profile {
    pub fn new() -> Result<Profile> {
        let name = format!("{:x}", rand::random::<u64>());
        let _tmp = TempDir::new(TMP_PREFIX)?;
        let home = match _tmp.as_ref().to_str() {
            Some(string) => string.to_string(),
            None => Err(Error::from(
                "failed get the &str representation of a temp directory created for a profile",
            ))?,
        };
        Ok(Profile { name, home, _tmp })
    }

    pub fn cert_storage(&self) -> Result<CertStorage> {
        self.cert_storage_path().try_into()
    }

    pub fn cert_storage_path(&self) -> PathBuf {
        Path::new(&self.home)
            .join(CERT_STORAGE_DIR)
            .join(CERT_STORAGE_DB)
    }
}
