const ENV: &str = "ENV";
const DEV: &str = "DEV";
const PROD: &str = "PROD";

pub fn prod() -> bool {
    match std::env::var(ENV).unwrap_or(DEV.to_string()).as_str() {
        DEV => false,
        PROD => true,
        unknown => panic!("unknown environment set, {}", unknown)
    }
}
