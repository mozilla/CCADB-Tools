use crate::errors::*;
use std::process::Child;

const XVFB_EXECUTABLE: &str = "Xvfb";
pub const DISPLAY_PORT: &str = ":99";

pub struct Xvfb {
    process: Child,
}

impl Xvfb {
    pub fn new() -> Result<Self> {
        Ok(Xvfb {
            process: std::process::Command::new(XVFB_EXECUTABLE)
                .arg(DISPLAY_PORT)
                .spawn()
                .chain_err(|| "failed to start Xvfb")?,
        })
    }
}

impl Drop for Xvfb {
    fn drop(&mut self) {
        match self.process.kill() {
            Ok(_) => (),
            Err(err) => eprintln!("{:?}", err),
        };
    }
}
