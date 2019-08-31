use crate::errors::*;
use serde::Deserialize;
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Deserialize)]
pub struct Issuer {
    pub common_name: String,
    pub organziation: String,
    pub error: Option<String>,
}

const EXECUTABLE: &str = "asn1";

pub fn parse_issuers(issuers: Vec<&str>) -> Result<Vec<Issuer>> {
    let mut issuers: String = issuers.join("\n");
    issuers.push_str("\n-1\n");
    let mut cmd = Command::new(EXECUTABLE)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    cmd.stdin.as_mut().unwrap().write_all(issuers.as_bytes())?;
    let out = String::from_utf8(cmd.wait_with_output()?.stdout)?;
    let mut issuers = vec![];
    for issuer in out.split("\n").into_iter().filter(|i| i.len() > 0) {
        issuers.push(serde_json::from_str::<Issuer>(issuer.as_ref())?)
    }
    Ok(issuers)
}
