use der_parser::der::{parse_der_sequence, DerTag};
use x509_parser::{X509Name, RelativeDistinguishedName, AttributeTypeAndValue};
use std::convert::TryFrom;
use der_parser::error::BerError;
use nom::IResult;
use der_parser::ber::*;
use nom::multi::many1;
use rusticata_macros::*;
use der_parser::*;
use der_parser::der::*;
use crate::errors::{IntegrityResult, IntegrityError};

const example: &str = "MDgxCzAJBgNVBAYTAkVTMRQwEgYDVQQKDAtJWkVOUEUgUy5BLjETMBEGA1UEAwwKSXplbnBlLmNvbQ==";

pub fn to_string<T: AsRef<[u8]>>(name: T) -> IntegrityResult<String> {
    let decoded = base64::decode(name.as_ref()).map_err(|err| IntegrityError::new("nope").with_err(err).with_context(
        ctx!(("raw_content", String::from_utf8_lossy(name.as_ref()).to_string()))
    ))?;
    Ok(parse_name(decoded.as_slice()).map_err(|err| IntegrityError::new("nope").with_err(err).with_context(
        ctx!(("raw_content", String::from_utf8_lossy(name.as_ref()).to_string()))
    ))?.1.to_string())
}

fn parse_name(i:&[u8]) -> IResult<&[u8],X509Name,BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        v: many1!(complete!(parse_rdn)) >>
        ( X509Name{ rdn_seq:v } )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_rdn(i:&[u8]) -> IResult<&[u8],RelativeDistinguishedName,BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Set,
        v: many1!(complete!(parse_attr_type_and_value)) >>
        ( RelativeDistinguishedName{ set:v } )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_attr_type_and_value(i:&[u8]) -> IResult<&[u8],AttributeTypeAndValue,BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        oid: map_res!(parse_der_oid, |x:DerObject| x.as_oid_val()) >>
        val: parse_directory_string >>
        ( AttributeTypeAndValue{ attr_type:oid, attr_value:val } )
    ).map(|(rem,x)| (rem,x.1))
}

#[inline]
fn parse_directory_string(i:&[u8]) -> IResult<&[u8],DerObject,BerError> {
    alt!(i,
         complete!(parse_der_utf8string) |
         complete!(parse_der_printablestring) |
         complete!(parse_der_ia5string) |
         complete!(parse_der_t61string) |
         complete!(parse_der_bmpstring))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asdasds() {
        println!("{}", to_string(example.as_bytes()).unwrap());
    }
}