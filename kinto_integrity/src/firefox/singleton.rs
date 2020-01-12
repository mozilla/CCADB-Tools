use crate::errors::*;
use crate::firefox::cert_storage::CertStorage;
use std::sync::{RwLockReadGuard, RwLockWriteGuard};

pub trait FirefoxRelease {
    const DISPLAY: &'static str;
    const DEBUG: &'static str;
    const URL: &'static str;

    fn get_mut(&self) -> Result<RwLockWriteGuard<crate::firefox::firefox::Firefox>>;
    fn get(&self) -> Result<RwLockReadGuard<crate::firefox::firefox::Firefox>>;

    fn update(&self) -> Result<()> {
        let mut inner = self.get_mut()?;
        match inner.update(Self::URL.parse().unwrap()) {
            Ok(None) => info!("No updates published to {}", Self::DISPLAY),
            Ok(Some(_)) => info!("Downloaded an update to {}", Self::DISPLAY),
            Err(err) => error!("{}", err.to_string()),
        }
        Ok(())
    }

    fn force_update(&self) -> Result<()> {
        self.get_mut()?.force_update(Self::URL.parse().unwrap())
    }

    fn cert_storage(&self) -> Result<CertStorage> {
        self.get()?.cert_storage()
    }

    fn update_cert_storage(&self) -> Result<()> {
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

            fn get_mut(&self) -> Result<RwLockWriteGuard<crate::firefox::firefox::Firefox>> {
                match self.write() {
                    Ok(guard) => Ok(guard),
                    Err(err) => Err(err.to_string())?,
                }
            }

            fn get(&self) -> Result<RwLockReadGuard<crate::firefox::firefox::Firefox>> {
                match self.read() {
                    Ok(guard) => Ok(guard),
                    Err(err) => Err(err.to_string())?,
                }
            }
        }
    };
}
