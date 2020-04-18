/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use rocket::http::Status;
use rocket::response::{Responder, ResponseBuilder};
use rocket::{Request, Response};
use std::convert::From;
use std::io::Cursor;
use std::string::FromUtf8Error;

#[macro_use]
pub mod new;

pub use new::*;

error_chain! {
    foreign_links {
        Fmt(::std::fmt::Error);
        Io(::std::io::Error);
        Reqwest(reqwest::Error);
        Infallible(std::convert::Infallible);
        Json(serde_json::error::Error);
        ASN1(simple_asn1::ASN1EncodeErr);
    }
}

impl std::convert::From<std::string::FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        format!("{:?}", err).into()
    }
}

impl std::convert::From<rkv::StoreError> for Error {
    fn from(err: rkv::StoreError) -> Self {
        format!("{:?}", err).into()
    }
}

impl<'a> Responder<'a> for Error {
    fn respond_to(self, _: &Request) -> std::result::Result<Response<'a>, Status> {
        Ok(ResponseBuilder::new(Response::new())
            .sized_body(Cursor::new(self.to_string()))
            .status(Status::InternalServerError)
            .finalize())
    }
}

use std::fmt::Formatter;

use error_chain::ChainedError;

pub struct FinalError {
    inner: Error,
}
impl std::error::Error for FinalError {}
impl std::fmt::Display for FinalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.inner.display_chain().to_string().as_str())
    }
}
impl std::fmt::Debug for FinalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.inner.display_chain().to_string().as_str())
    }
}

impl From<Error> for FinalError {
    fn from(err: Error) -> Self {
        Self { inner: err }
    }
}

impl From<serde_json::error::Error> for FinalError {
    fn from(err: serde_json::error::Error) -> Self {
        Self {
            inner: (err.to_string().into()),
        }
    }
}

impl From<String> for FinalError {
    fn from(err: String) -> Self {
        Self { inner: err.into() }
    }
}

impl From<IntegrityError> for FinalError {
    fn from(err: IntegrityError) -> Self {
        Self {
            inner: format!("{}", err).into(),
        }
    }
}

pub type FinalResult<T> = std::result::Result<T, FinalError>;

impl<'r> Responder<'r> for FinalError {
    fn respond_to(self, request: &Request) -> rocket::response::Result<'r> {
        Response::build()
            .sized_body(Cursor::new(self.to_string()))
            .status(Status::Locked)
            .ok()
    }
}
