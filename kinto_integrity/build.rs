use std::io::{BufReader, Cursor, Read, Write};
use std::path::PathBuf;

const GO_DARWIN: &str = "https://dl.google.com/go/go1.12.9.darwin-amd64.tar.gz";
const GO_LINUX: &str = "";
const GO_WINDOWS: &str = "https://dl.google.com/go/go1.12.9.windows-amd64.zip";
const GO_DIR: &str = "go";

fn main() {
//    if !already_bootstrapped() {
//        get_go();
//    }
    //    make_go();
}

fn make_go() {
    let compiler = "go/bin/go.exe";
    let mut cwd = std::env::current_dir().unwrap();
    cwd.push("go");
    cwd.push("src");
    let mut child = std::process::Command::new(compiler)
        .env_clear()
        .current_dir(std::env::current_dir().unwrap())
        .env("GOPATH", cwd.as_path())
        .arg("build")
        .arg("src/model/asn1/asn1.go")
        .spawn()
        .unwrap();
    child.wait().unwrap();
    let mut dst = PathBuf::new();
    dst.push("src");
    dst.push("model");
    dst.push("asn1");
    dst.push("asn1");
    let mut exe = std::env::current_dir().unwrap();
    exe.push("asn1.exe");
    std::fs::rename(exe, dst).unwrap();
}

fn already_bootstrapped() -> bool {
    std::fs::metadata(GO_DIR).is_ok()
}

const UNZIP: &str = "Expand-Archive";
#[cfg(windows)]
fn get_go() {
    let cwd = std::env::current_dir().unwrap();
    let mut zip = vec![];
    let mut resp = reqwest::get(GO_WINDOWS).unwrap();
    resp.read_to_end(&mut zip).unwrap();
    let mut reader = Cursor::new(zip);
    let mut tmp = tempdir::TempDir::new_in(cwd.as_path(), "kinto_integrity_build").unwrap();
    unzip::Unzipper::new(reader, tmp.path()).unzip().unwrap();
    let mut src = PathBuf::new();
    src.push(tmp.path());
    src.push("go");
    let mut dst = std::env::current_dir().unwrap();
    dst.push(GO_DIR);
    std::fs::rename(src, dst).unwrap();
}

#[cfg(linux)]
fn get_go() {
    let mut resp = reqwest::get(GO_LINUX).unwrap();
    tar::Archive::new(bzip2::bufread::BzDecoder::new(BufReader::new(resp)))
        .unpack(GO_DIR)
        .unwrap();
}

#[cfg(macos)]
fn get_go() {}
