/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use lazy_static;

use crate::errors::*;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;
use xvfb::Xvfb;

pub mod cert_storage;
pub mod profile;
pub mod firefox;

mod xvfb;

#[macro_use]
mod singleton;
pub use singleton::*;


lazy_static! {
    static ref XVFB: Xvfb = Xvfb::new().unwrap();
}

firefox_release!(
    FIREFOX_NIGHTLY,
    "Firefox Nightly",
    "firefox_nightly",
    "https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=linux64&lang=en-US"
);

firefox_release!(
    FIREFOX_BETA,
    "Firefox Beta",
    "firefox_beta",
    "https://download.mozilla.org/?product=firefox-beta-latest-ssl&os=linux64&lang=en-US"
);

pub fn init() {
    info!(
        "Starting the X Virtual Frame Buffer on DISPLAY={}",
        xvfb::DISPLAY_PORT
    );
    let _ = *XVFB;
    std::thread::spawn(|| loop {
        FIREFOX_NIGHTLY.update();
        std::thread::sleep(Duration::from_secs(60 * 60));
    });
    std::thread::spawn(|| loop {
        FIREFOX_BETA.update();
        std::thread::sleep(Duration::from_secs(60 * 60));
    });
}


