

use std::fmt::{Error, Formatter, Debug};
use rocket::response::{Responder, ResponseBuilder};
use rocket::{Response, Request};
use rocket::http::Status;
use std::collections::HashMap;
use std::io::Cursor;
use serde::export::fmt::Display;
use serde::Serialize;

type MozillaMessage = String;
type ExternalMessage = Option<String>;

pub type IntegrityResult<T> = Result<T, IntegrityError>;

#[derive(Serialize)]
pub struct IntegrityError {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<&'static str, String>>,
    #[serde(skip)]
    pub status: Status,
}


impl IntegrityError {
    pub fn nnew<T: Display>(msg: T) -> Self {
        Self {
            message: format!("{}", msg),
            err: None,
            context: None,
            status: rocket::http::Status::BadGateway
        }
    }
    pub fn new<T: Display>(msg: T, status: Status) -> Self {
        IntegrityError{
            message: format!("{}", msg),
            err: None,
            context: None,
            status
        }
    }
    pub fn raw<T: Display>(mut self, raw: T) -> Self {
        self.err = Some(format!("{}", raw));
        self
    }
    pub fn context(mut self, context: HashMap<&'static str, String>) -> Self {
        self.context = Some(context);
        self
    }
}

impl From<&'static str> for IntegrityError {
    fn from(msg: &'static str) -> Self {
        Self{
            message: msg.to_string(),
            err: None,
            context: None,
            status: Status::BadGateway
        }
    }
}

impl From<String> for IntegrityError {
    fn from(msg: String) -> Self {
        Self{
            message: msg,
            err: None,
            context: None,
            status: Status::BadGateway
        }
    }
}

impl <'r> Responder<'r> for IntegrityError {
    fn respond_to(self, _: &Request) -> rocket::response::Result<'r> {
        ResponseBuilder::new(Response::new()).status(self.status).sized_body(Cursor::new(format!("{}", self))).ok()
    }
}

impl std::error::Error for IntegrityError {}

impl std::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(serde_json::to_string_pretty(self).unwrap().as_str())
    }
}

#[derive(Serialize)]
struct Serializable<'a> {
    pub message: MozillaMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: &'a ExternalMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: &'a Option<HashMap<&'static str, String>>,
    pub status: String,
}

impl std::fmt::Debug for IntegrityError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(format!("{}", self).as_str())
    }
}

#[macro_export]
macro_rules! ctx {
    ( $($c:expr),*) => {{
        let mut map: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
        $(
            map.insert($c.0, format!("{}", $c.1));
        )*
        map
    }};
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() -> IntegrityResult<()> {
        Err(IntegrityError::new("balls", Status::NotFound).context(ctx!(("1", 1), ("got", "error"))).raw("badddd mojo"))
    }
}