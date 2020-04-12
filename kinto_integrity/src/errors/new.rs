

use std::fmt::{Error, Formatter, Debug};
use rocket::response::{Responder, ResponseBuilder};
use rocket::{Response, Request};
use rocket::http::Status;
use std::collections::HashMap;
use std::io::Cursor;
use serde::export::fmt::Display;
use serde::Serialize;

type MozillaMessage = &'static str;
type ExternalMessage = Option<String>;

pub type IntegrityResult<T> = Result<T, IntegrityError>;

pub struct IntegrityError {
    pub mozilla: MozillaMessage,
    pub _raw: ExternalMessage,
    pub context: Option<HashMap<&'static str, String>>,
    pub status: Status,
}


impl IntegrityError {
    pub fn new(msg: &'static str, status: Status) -> Self {
        IntegrityError{
            mozilla: msg,
            _raw: None,
            context: None,
            status
        }
    }
    pub fn raw<T: Display>(mut self, raw: T) -> Self {
        self._raw = Some(format!("{}", raw));
        self
    }
    pub fn context(mut self, context: HashMap<&'static str, String>) -> Self {
        self.context = Some(context);
        self
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
        let s = Serializable{
            message: self.mozilla,
            raw: &self._raw,
            context: &self.context,
            status: self.status.to_string()
        };
        f.write_str(serde_json::to_string_pretty(&s).unwrap().as_str())
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