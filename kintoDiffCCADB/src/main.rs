#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;

use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use futures::future::{ok, Future};

mod firefox;
mod updater;


mod errors {
    use actix_web::http;
    use std::convert::From;
    error_chain! {}

    impl From<reqwest::Error> for Error {
        fn from(err: reqwest::Error) -> Self {
            format!("{:?}", err).into()
        }
    }

    impl From<std::io::Error> for Error {
        fn from(err: std::io::Error) -> Self {
            format!("{:?}", err).into()
        }
    }

    impl From<std::convert::Infallible> for Error {
        fn from(err: std::convert::Infallible) -> Self {
            format!("{:?}", err).into()
        }
    }
}


fn index(info: web::Path<(u32, String)>) -> impl Responder {
    format!("Hello {}! id:{}", info.1, info.0)
}


fn main() -> std::io::Result<()> {
    HttpServer::new(
        || App::new().service(
              web::resource("/{id}/{name}/index.html").to(index)))
        .bind("127.0.0.1:8080")?
        .run()
}

