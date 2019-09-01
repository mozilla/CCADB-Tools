use crate::errors::*;
use serde::Deserialize;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

#[derive(Deserialize)]
pub struct Issuer {
    pub common_name: String,
    pub organization: String,
    pub error: Option<String>,
}

//const EXECUTABLE: &str = "asn1";
//
//const EXE: &'static [u8] = include_bytes!("asn1");
//
//lazy_static! {
//    static ref TOOL: NamedTempFile = expand_go_tool();
//}
//
//fn expand_go_tool() -> NamedTempFile {
//    let mut tool = NamedTempFile::new().unwrap();
//    tool.write_all(EXE).unwrap();
//    tool.close().unwrap();
//    tool
//}

pub fn parse_issuers(issuers: Vec<&str>) -> Result<Vec<Issuer>> {
    let mut issuers: String = issuers.join("\n");
    issuers.push_str("\n-1\n");
    let mut cmd = Command::new(r#"asn1"#)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdfsdf() {
        parse_issuers(vec![]).unwrap();
    }
}
