fn main() {
    build_go();
}

fn build_go() {
    let _ = std::fs::remove_dir_all("target/lib/x509");
    std::fs::create_dir_all("target/lib/x509").unwrap();
    std::process::Command::new("go").arg("build").arg("-o").arg("../../target/lib/x509/x509").current_dir("src/x509").output().unwrap();
}