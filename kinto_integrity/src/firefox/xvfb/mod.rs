/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::errors::{IntegrityError, IntegrityResult};
use std::process::Child;

const XVFB_EXECUTABLE: &str = "Xvfb";
pub const DISPLAY_PORT: &str = ":99";

pub struct Xvfb {
    process: Child,
}

impl Xvfb {
    pub fn new() -> IntegrityResult<Self> {
        let _ = std::fs::remove_file("/tmp/.X99-lock");
        Ok(Xvfb {
            process: std::process::Command::new(XVFB_EXECUTABLE)
                .arg(DISPLAY_PORT)
                .spawn()
                .map_err(|err| IntegrityError::new("Failed to start Xvfb").with_err(err))?,
        })
    }
}

impl Drop for Xvfb {
    fn drop(&mut self) {
        info!("Stopping the Xvfb server");
        match self.process.kill() {
            Ok(_) => (),
            Err(err) => error!("{:?}", err),
        };
        let _ = std::fs::remove_file("/tmp/.X99-lock");
    }
}
