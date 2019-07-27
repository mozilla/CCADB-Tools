use crate::errors::*;
use crate::firefox;
use reqwest::{Client, ClientBuilder, RedirectPolicy, Url};
use std::convert::TryInto;
use std::thread::{JoinHandle, Thread};
use std::time::Duration;

pub(crate) fn main() -> JoinHandle<()> {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(60 * 60));
        match firefox::FIREFOX.lock() {
            Ok(mut ff) => {
                match ff.update() {
                    Ok(_) => (),
                    Err(err) => println!("{:?}", err)
                }
            }
            Err(err) => println!("{:?}", err)
        }
    })
//    println!("Updating! {}", "asdas");
//    let mut previous = get_latest((*firefox::NIGHTLY).clone()).unwrap();
//    println!("Updating! {}", "asdas");
//    update(&previous);
//    std::thread::spawn(move || loop {
//        std::thread::sleep(Duration::from_secs(60 * 60));
//        let latest = get_latest((*firefox::NIGHTLY).clone());
//        match latest {
//            Ok(location) => {
//                if !location.eq(&previous) {
//                    previous = location;
//                    update(&previous);
//                } else {
//                    println!("Not updating")
//                }
//            }
//            Err(err) => println!("{}", err),
//        };
//    })
}

fn get_latest(latest: Url) -> Result<Url> {
    let client = ClientBuilder::new()
        .redirect(RedirectPolicy::none())
        .build()
        .unwrap();
    let resp = client.get(latest).send().unwrap();
    if let Some(redirect) = resp.headers().get("location") {
        match redirect.to_str() {
            Ok(redirect) => match redirect.parse() {
                Ok(url) => Ok(url),
                Err(err) => Err(Error::from(err.to_string())),
            },
            Err(err) => Err(Error::from(err.to_string())),
        }
    } else {
        Err(Error::from(
            "no location header is present for a redirect notice",
        ))
    }
}

fn update(latest: &Url) {
    let ff: firefox::Firefox = latest.clone().try_into().unwrap();
    *firefox::FIREFOX.lock().unwrap() = ff;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asdasd() {
        println!("{:?}", get_latest((*firefox::NIGHTLY).clone()));
    }

    #[test]
    fn asdfdasd() {
        main().join();
    }
}
