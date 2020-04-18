use crate::errors::*;
use reqwest::Url;
use serde::Deserialize;
use std::io::Write;
use std::process::Child;
use std::sync::RwLock;

pub mod name;

static TOOL: &[u8] = include_bytes!("../../target/lib/x509/x509");

lazy_static! {
    static ref URL: RwLock<Url> = RwLock::new(Url::parse("http://localhost").unwrap());
}

pub fn init() -> Result<Child> {
    let tmp = match tempfile::NamedTempFile::new() {
        Ok(tmp) => tmp,
        Err(err) => Err(err.to_string())?,
    };
    let (mut file, path) = match tmp.keep() {
        Ok(ret) => ret,
        Err(err) => Err(err.to_string())?,
    };
    file.write(TOOL)?;
    let port = match crate::get_port()? {
        std::u16::MAX => std::u16::MAX - 1,
        port => port + 1,
    };
    drop(file);
    std::process::Command::new("chmod")
        .arg("+x")
        .arg(path.as_path())
        .output()
        .unwrap();
    *URL.write().unwrap() =
        reqwest::Url::parse(format!("http://localhost:{}/", port).as_ref()).unwrap();
    Ok(std::process::Command::new(path.as_path())
        .env("GO_PORT", port.to_string())
        .spawn()?)
}

#[derive(Deserialize)]
struct Response {
    rdn: String,
    error: String,
}

pub fn b64_to_rdn<T: AsRef<[u8]>>(b64: T) -> IntegrityResult<String> {
    name::to_string(b64)
    // let resp: Response = reqwest::blocking::Client::new()
    //     .post(URL.read().unwrap().clone())
    //     .body(b64)
    //     .send()?
    //     .json()?;
    // match resp.rdn.as_str() {
    //     "" => Err(resp.error.into()),
    //     _ => Ok(resp.rdn),
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        let mut child = init().unwrap();
        let result = b64_to_rdn(
            "MDgxCzAJBgNVBAYTAkVTMRQwEgYDVQQKDAtJWkVOUEUgUy5BLjETMBEGA1UEAwwKSXplbnBlLmNvbQ==",
        );
        child.kill().unwrap();
        match result {
            Err(err) => panic!(err),
            Ok(rdn) => assert_eq!(rdn, "CN=Izenpe.com,O=IZENPE S.A.,C=ES"),
        }
    }
}
