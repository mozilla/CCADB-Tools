use reqwest::{Url, Client, ClientBuilder, RedirectPolicy};
use crate::firefox;
use crate::errors::*;
use std::thread::{Thread, JoinHandle};
use std::time::Duration;
use std::convert::TryInto;

fn main() -> JoinHandle<()> {
            println!("Updating! {}", "asdas");
    let mut previous = get_latest((*firefox::NIGHTLY).clone()).unwrap();
     println!("Updating! {}", "asdas");
    update(&previous);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(60 * 60));
            let latest = get_latest((*firefox::NIGHTLY).clone());
            match latest {
                Ok(location) => {
                    if !location.eq(&previous) {
                        previous = location;
                        update(&previous);
                    } else {
                        println!("Not updating")
                    }
                },
                Err(err) => println!("{}", err)
            };
        }
    })
}

fn get_latest(latest: Url) -> Result<Url> {
    let client = ClientBuilder::new().redirect(RedirectPolicy::none()).build().unwrap();
    let resp = client.get(latest).send().unwrap();
    if let Some(redirect) = resp.headers().get("location") {
        match redirect.to_str() {
            Ok(redirect) => {
                match redirect.parse() {
                    Ok(url) => Ok(url),
                    Err(err) => Err(Error::from(err.to_string()))
                }
            },
            Err(err) => Err(Error::from(err.to_string()))
        }
    } else {
        Err(Error::from("no location header is present for a redirect notice"))
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