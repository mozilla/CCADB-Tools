/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::errors::*;
use crate::firefox::cert_storage::CertStorage;
use std::sync::{RwLockReadGuard, RwLockWriteGuard};

pub trait FirefoxRelease {
    const DISPLAY: &'static str;
    const DEBUG: &'static str;
    const URL: &'static str;

    fn get_mut(&self) -> IntegrityResult<RwLockWriteGuard<crate::firefox::firefox::Firefox>>;
    fn get(&self) -> IntegrityResult<RwLockReadGuard<crate::firefox::firefox::Firefox>>;

    fn update(&self) -> IntegrityResult<()> {
        let mut inner = self.get_mut()?;
        // std::sync::TryLockError::Poisoned(err)
        match inner.update(Self::URL.parse().unwrap()) {
            Ok(None) => info!("No updates published to {}", Self::DISPLAY),
            Ok(Some(_)) => info!("Downloaded an update to {}, it is now ready to use", Self::DISPLAY),
            Err(err) => error!("{}", err.to_string()),
        }
        Ok(())
    }

    fn force_update(&self) -> IntegrityResult<()> {
        self.get_mut()?.force_update(Self::URL.parse().unwrap())
    }

    fn cert_storage(&self) -> IntegrityResult<CertStorage> {
        self.get()?.cert_storage()
    }

    fn update_cert_storage(&self) -> IntegrityResult<()> {
        self.get_mut()?.update_cert_storage()
    }
}

#[macro_export]
macro_rules! firefox_release {
    ($release:ident, $display:expr, $debug:expr, $url:expr) => {
        lazy_static! {
            pub static ref $release: RwLock<crate::firefox::firefox::Firefox> =
                RwLock::new(crate::firefox::firefox::Firefox::default());
        }

        impl FirefoxRelease for $release {
            const DISPLAY: &'static str = $display;
            const DEBUG: &'static str = $debug;
            const URL: &'static str = $url;

            fn get_mut(
                &self,
            ) -> IntegrityResult<RwLockWriteGuard<crate::firefox::firefox::Firefox>> {
                match self.write() {
                    Ok(guard) => Ok(guard),
                    Err(err) => Err(err.to_string())?,
                }
            }

            fn get(&self) -> IntegrityResult<RwLockReadGuard<crate::firefox::firefox::Firefox>> {
                match self.try_read() {
                    Ok(guard) => Ok(guard),
                    Err(std::sync::TryLockError::Poisoned(err)) => Err(err.to_string())?,
                    Err(std::sync::TryLockError::WouldBlock) => Err("Firefox is still in the middle of initializing itself with an up-to-date cert_storage, please try again later.")?,
                }
            }
        }
    };
}
