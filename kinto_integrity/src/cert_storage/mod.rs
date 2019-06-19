use crate::errors::*;
use crate::intermediary::Intermediary;
use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use lmdb::EnvironmentFlags;
use rkv::{Rkv, StoreOptions, Value};
use std::collections::{BTreeSet, HashSet};
use std::hash::Hash;

pub struct CertStorage {
    pub data: HashSet<IssuerSerial>,
}

#[derive(Eq, PartialEq, Hash)]
pub struct IssuerSerial {
    pub issuer_name: String,
    pub serial: String
}

impl TryFrom<PathBuf> for CertStorage {
    type Error = Error;

    fn try_from(mut db_path: PathBuf) -> Result<Self> {
        let mut builder = Rkv::environment_builder();
        builder.set_max_dbs(2);
        builder.set_flags(EnvironmentFlags::READ_ONLY);
        db_path.push("security_state");
        let env = Rkv::from_env(&db_path, builder).unwrap();
        let store = env.open_single("cert_storage", StoreOptions::default()).unwrap();
        let reader =  env.read().unwrap();
        let iter = store.iter_start(&reader).unwrap();
        let mut revocations = CertStorage{data: HashSet::new()};
        for item in iter {
            if let Ok((key, value)) = item {
                match decode_item(key, &value) {
                    Some(Ok(intermediary)) => {revocations.data.insert(intermediary);},
                    Some(Err(err)) => {Err(err).chain_err(|| "failed to build set from cert_storage")?;},
                    None => (),
                };
            }
        }
        Ok(revocations)
    }
}

const PREFIX_REV_IS: &[u8] = b"is";

fn decode_item(key: &[u8], value: &Option<Value>) -> Option<Result<IssuerSerial>> {
    if has_prefix(key, PREFIX_REV_IS) {
        decode_revocation(
            &key[PREFIX_REV_IS.len()..],
            value)
    } else {
        None
    }
}

fn has_prefix(data: &[u8], prefix: &[u8]) -> bool {
    if data.len() >= prefix.len() {
        return &data[..prefix.len()] == prefix;
    }
    false
}

fn decode_revocation(
    key: &[u8],
    value: &Option<Value>
) -> Option<Result<IssuerSerial>> {
    match value {
        &Some(Value::I64(i)) if i == 1 => {}
        &Some(Value::I64(i)) if i == 0 => return None,
        &None => return None,
        &Some(_) => return None,
    }
    Some(match split_der_key(key) {
        Ok((part1, part2)) => {
            Ok(IssuerSerial {
                issuer_name: base64::encode(part1),
                serial: base64::encode(part2),
            })
        }
        Err(e) => Err(e),
    })
}

fn split_der_key(key: &[u8]) -> Result<(&[u8], &[u8])> {
    if key.len() < 2 {
        panic!("key too short to be DER");
    }
    let first_len_byte = key[1] as usize;
    if first_len_byte < 0x80 {
        if key.len() < first_len_byte + 2 {
            panic!("key too short");
        }
        return Ok(key.split_at(first_len_byte + 2 as usize));
    }
    if first_len_byte == 0x80 {
        panic!("unsupported ASN.1");
    }
    if first_len_byte == 0x81 {
        if key.len() < 3 {
            panic!("key too short to be DER");
        }
        let len = key[2] as usize;
        if len < 0x80 {
            panic!("bad DER");
        }
        if key.len() < len + 3 {
            panic!("key too short");
        }
        return Ok(key.split_at(len + 3));
    }
    if first_len_byte == 0x82 {
        if key.len() < 4 {
            panic!("key too short to be DER");
        }
        let len = (key[2] as usize) << 8 | key[3] as usize;
        if len < 256 {
            panic!("bad DER");
        }
        if key.len() < len + 4 {
            panic!("key too short");
        }
        return Ok(key.split_at(len + 4));
    }
    panic!("key too long");
}

//extern crate base64;
//#[macro_use]
//extern crate clap;
//extern crate curl;
//extern crate cert_storage;
//extern crate rkv;
//extern crate serde_json;
//
//use clap::App;
//use curl::easy::Easy;
//use cert_storage::EnvironmentFlags;
//use rkv::{Rkv, StoreOptions, Value};
//use serde_json::Value as JsonValue;
//use std::collections::BTreeSet;
//use std::fmt::Display;
//use std::path::PathBuf;
//
//
//
//struct SimpleError {
//    message: String,
//}
//
//impl<T: Display> From<T> for SimpleError {
//    fn from(err: T) -> SimpleError {
//        SimpleError {
//            message: format!("{}", err),
//        }
//    }
//}
//
//const DEFAULT_ONECRL_URL: &str = "https://firefox.settings.services.mozilla.com/v1/\
//                                  buckets/security-state/collections/onecrl/records";
//
//fn main() {
//    let yaml = load_yaml!("cli.yml");
//    let matches = App::from_yaml(yaml).get_matches();
//    let onecrl_url = matches.value_of("onecrl-url").unwrap_or(DEFAULT_ONECRL_URL);
//    let profile_path = matches
//        .value_of("profile-path")
//        .unwrap_or(r#"C:\Users\Christopher Henderso\AppData\Roaming\Mozilla\Firefox\Profiles\b1e6quep.default-nightly"#);
//    if let Err(e) = do_it(onecrl_url, profile_path) {
//        eprintln!("{}", e.message);
//    }
//}
//
//fn do_it(onecrl_url: &str, profile_path: &str) -> Result<(), SimpleError> {
//    let current_revocations = download_current_revocations(onecrl_url)?;
//    println!("current OneCRL revocations: {}", current_revocations.len());
//    let revocations_in_profile = read_profile_revocations(profile_path)?;
//    println!("revocations in profile: {}", revocations_in_profile.len());
//    println!("revocations in OneCRL but not in profile:");
//    for revocation in current_revocations.difference(&revocations_in_profile) {
//        println!("{:?}", revocation);
//    }
//    println!("revocations in profile but not in OneCRL:");
//    for revocation in revocations_in_profile.difference(&current_revocations) {
//        println!("{:?}", revocation);
//    }
//    Ok(())
//}
//
//fn read_profile_revocations(profile_path: &str) -> Result<BTreeSet<Revocation>, SimpleError> {
//    let mut builder = Rkv::environment_builder();
//    builder.set_max_dbs(2);
//    builder.set_flags(EnvironmentFlags::READ_ONLY);
//    let mut db_path = PathBuf::from(profile_path);
//    db_path.push("security_state");
//    let env = Rkv::from_env(&db_path, builder)?;
//    let store = env.open_single("cert_storage", StoreOptions::default())?;
//    let reader = env.read()?;
//    let iter = store.iter_start(&reader)?;
//    let mut revocations: BTreeSet<Revocation> = BTreeSet::new();
//    for item in iter {
//        if let Ok((key, value)) = item {
//            decode_item(key, &value, &mut revocations);
//        }
//    }
//    Ok(revocations)
//}
//
//#[derive(Ord, Eq, PartialOrd, PartialEq, Debug)]
//enum RevocationType {
//    IssuerSerial,
//    SubjectPublicKey,
//}
//
//const PREFIX_REV_IS: &[u8] = b"is";
//const PREFIX_REV_SPK: &[u8] = b"spk";
//
//fn has_prefix(data: &[u8], prefix: &[u8]) -> bool {
//    if data.len() >= prefix.len() {
//        return &data[..prefix.len()] == prefix;
//    }
//    false
//}
//
//fn decode_item(key: &[u8], value: &Option<Value>, revocations: &mut BTreeSet<Revocation>) {
//    if has_prefix(key, PREFIX_REV_IS) {
//        decode_revocation(
//            &key[PREFIX_REV_IS.len()..],
//            value,
//            RevocationType::IssuerSerial,
//            revocations,
//        );
//    } else if has_prefix(key, PREFIX_REV_SPK) {
//        decode_revocation(
//            &key[PREFIX_REV_SPK.len()..],
//            value,
//            RevocationType::SubjectPublicKey,
//            revocations,
//        );
//    }
//}
//
//fn split_der_key(key: &[u8]) -> Result<(&[u8], &[u8]), SimpleError> {
//    if key.len() < 2 {
//        return Err(SimpleError::from("key too short to be DER"));
//    }
//    let first_len_byte = key[1] as usize;
//    if first_len_byte < 0x80 {
//        if key.len() < first_len_byte + 2 {
//            return Err(SimpleError::from("key too short"));
//        }
//        return Ok(key.split_at(first_len_byte + 2 as usize));
//    }
//    if first_len_byte == 0x80 {
//        return Err(SimpleError::from("unsupported ASN.1"));
//    }
//    if first_len_byte == 0x81 {
//        if key.len() < 3 {
//            return Err(SimpleError::from("key too short to be DER"));
//        }
//        let len = key[2] as usize;
//        if len < 0x80 {
//            return Err(SimpleError::from("bad DER"));
//        }
//        if key.len() < len + 3 {
//            return Err(SimpleError::from("key too short"));
//        }
//        return Ok(key.split_at(len + 3));
//    }
//    if first_len_byte == 0x82 {
//        if key.len() < 4 {
//            return Err(SimpleError::from("key too short to be DER"));
//        }
//        let len = (key[2] as usize) << 8 | key[3] as usize;
//        if len < 256 {
//            return Err(SimpleError::from("bad DER"));
//        }
//        if key.len() < len + 4 {
//            return Err(SimpleError::from("key too short"));
//        }
//        return Ok(key.split_at(len + 4));
//    }
//    Err(SimpleError::from("key too long"))
//}
//
//fn decode_revocation(
//    key: &[u8],
//    value: &Option<Value>,
//    typ: RevocationType,
//    revocations: &mut BTreeSet<Revocation>,
//) {
//    match value {
//        &Some(Value::I64(i)) if i == 1 => {}
//        &Some(Value::I64(i)) if i == 0 => return,
//        &None => return,
//        &Some(_) => {
//            eprintln!("unexpected value type for revocation entry");
//            return;
//        }
//    }
//    match split_der_key(key) {
//        Ok((part1, part2)) => {
//            let revocation = Revocation {
//                typ,
//                field1: base64::encode(part1),
//                field2: base64::encode(part2),
//            };
//            if revocations.contains(&revocation) {
//                eprintln!("duplicate entry in profile? ({:?})", revocation);
//            } else {
//                revocations.insert(revocation);
//            }
//        }
//        Err(e) => eprintln!("error decoding key: {}", e.message),
//    }
//}
//
//#[derive(Ord, Eq, PartialOrd, PartialEq, Debug)]
//struct Revocation {
//    typ: RevocationType,
//    field1: String,
//    field2: String,
//}
//
//fn download_current_revocations(onecrl_url: &str) -> Result<BTreeSet<Revocation>, SimpleError> {
//    let mut easy = Easy::new();
//    easy.url(onecrl_url)?;
//    let mut data = Vec::new();
//    {
//        let mut transfer = easy.transfer();
//        transfer.write_function(|new_data| {
//            data.extend_from_slice(new_data);
//            Ok(new_data.len())
//        })?;
//        transfer.perform()?;
//    }
//    let records: JsonValue = serde_json::from_slice(&data)?;
//    let records = records
//        .as_object()
//        .ok_or(SimpleError::from("unexpected type"))?;
//    let data = records
//        .get("data")
//        .ok_or(SimpleError::from("missing data key"))?;
//    let data = data
//        .as_array()
//        .ok_or(SimpleError::from("unexpected type"))?;
//    let mut revocations: BTreeSet<Revocation> = BTreeSet::new();
//    for entry in data {
//        let entry = entry
//            .as_object()
//            .ok_or(SimpleError::from("unexpected type"))?;
//        let revocation = if entry.contains_key("issuerName") && entry.contains_key("serialNumber") {
//            let issuer = entry
//                .get("issuerName")
//                .ok_or(SimpleError::from("couldn't get issuerName"))?;
//            let issuer = issuer
//                .as_str()
//                .ok_or(SimpleError::from("issuerName not a string"))?;
//            let serial = entry
//                .get("serialNumber")
//                .ok_or(SimpleError::from("couldn't get serialNumber"))?;
//            let serial = serial
//                .as_str()
//                .ok_or(SimpleError::from("serialNumber not a string"))?;
//            Revocation {
//                typ: RevocationType::IssuerSerial,
//                field1: issuer.to_owned(),
//                field2: serial.to_owned(),
//            }
//        } else if entry.contains_key("subject") && entry.contains_key("pubKeyHash") {
//            // TODO: I'm not actually sure about these field names, because there aren't any
//            // examples of them in the current data set.
//            let subject = entry
//                .get("subject")
//                .ok_or(SimpleError::from("couldn't get subject"))?;
//            let subject = subject
//                .as_str()
//                .ok_or(SimpleError::from("subject not a string"))?;
//            let pub_key_hash = entry
//                .get("pubKeyHash")
//                .ok_or(SimpleError::from("couldn't get pubKeyHash"))?;
//            let pub_key_hash = pub_key_hash
//                .as_str()
//                .ok_or(SimpleError::from("pubKeyHash not a string"))?;
//            Revocation {
//                typ: RevocationType::SubjectPublicKey,
//                field1: subject.to_owned(),
//                field2: pub_key_hash.to_owned(),
//            }
//        } else {
//            eprintln!("entry with no issuer/serial or no subject/pubKeyHash");
//            continue;
//        };
//        if revocations.contains(&revocation) {
//            eprintln!("duplicate entry in OneCRL? ({:?})", revocation);
//        } else {
//            revocations.insert(revocation);
//        }
//    }
//    Ok(revocations)
//}
