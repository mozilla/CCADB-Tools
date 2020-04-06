use crate::errors::*;
use rkv::{Value, Rkv, StoreOptions};
use std::convert::TryFrom;
use std::path::PathBuf;
use rkv::backend::{SafeMode, BackendEnvironmentBuilder};
use std::collections::HashSet;
use rayon::prelude::*;
use crate::model::Revocation;

pub struct CertStorage {
    pub data: Vec<Entry>,
}

impl Into<HashSet<Revocation>> for CertStorage {
    fn into(self) -> HashSet<Revocation> {
        self.data.into_par_iter().map(|entry| entry.into()).collect()
    }
}

impl TryFrom<PathBuf> for CertStorage {
    type Error = Error;

    fn try_from(db_path: PathBuf) -> Result<Self> {
        let mut revocations = CertStorage { data: vec![] };
        let mut builder = Rkv::environment_builder::<SafeMode>();
        builder.set_max_dbs(2);
        builder.set_map_size(16777216);
        let env = match Rkv::from_builder(&db_path, builder) {
            Err(err) => Err(format!("{}", err))?,
            Ok(env) => env,
        };
        let store = env.open_single("cert_storage", StoreOptions::default())?;
        let reader = env.read()?;
        for item in store.iter_start(&reader)? {
            let (key, value) = item?;
            match decode(key, value)? {
                Some(entry) => revocations.data.push(entry),
                None => ()
            };
        }
        Ok(revocations)
    }
}

fn decode(key: &[u8], value: Option<Value>) -> Result<Option<Entry>> {
    match value {
        Some(Value::I64(1)) => (),
        Some(Value::I64(0)) => return Ok(None),
        None => return Ok(None),
        Some(_) => return Ok(None),
    };
    Ok(match key {
        [b'i', b's', entry @ ..] => Some(Entry::issuer_serial_from(split_der_key(entry)?)),
        [b's', b'p', b'k', entry @ ..] => Some(Entry::subject_key_hash_from(split_der_key(entry)?)),
        _ => None
    })
}

pub enum Entry {
    IssuerSerial {
        issuer: String,
        serial: String
    },
    SubjectKeyHash {
        subject: String,
        key_hash: String
    }
}

impl Entry {
    fn issuer_serial_from(parts: (&[u8], &[u8])) -> Entry {
        Entry::IssuerSerial {
            issuer: base64::encode(parts.0),
            serial: base64::encode(parts.1)
        }
    }

    fn subject_key_hash_from(parts: (&[u8], &[u8])) -> Entry {
        Entry::SubjectKeyHash {
            subject: base64::encode(parts.0),
            key_hash: base64::encode(parts.1)
        }
    }
}

impl Into<crate::model::Revocation> for Entry {
    fn into(self) -> Revocation {
        match self {
            Entry::IssuerSerial {
                issuer,
                serial
            } => Revocation::new_issuer_serial(issuer, serial, None),
            Entry::SubjectKeyHash {
                subject,
                key_hash
            } => Revocation::new_subject_key_hash(subject, key_hash, None)
        }
    }
}

fn split_der_key(key: &[u8]) -> Result<(&[u8], &[u8])> {
    if key.len() < 2 {
        return Err("key too short to be DER".into());
    }
    let first_len_byte = key[1] as usize;
    if first_len_byte < 0x80 {
        if key.len() < first_len_byte + 2 {
            return Err("key too short".into());
        }
        return Ok(key.split_at(first_len_byte + 2 as usize));
    }
    if first_len_byte == 0x80 {
        return Err("unsupported ASN.1".into());
    }
    if first_len_byte == 0x81 {
        if key.len() < 3 {
            return Err("key too short to be DER".into());
        }
        let len = key[2] as usize;
        if len < 0x80 {
            return Err("bad DER".into());
        }
        if key.len() < len + 3 {
            return Err("key too short".into());
        }
        return Ok(key.split_at(len + 3));
    }
    if first_len_byte == 0x82 {
        if key.len() < 4 {
            return Err("key too short to be DER".into());
        }
        let len = (key[2] as usize) << 8 | key[3] as usize;
        if len < 256 {
            return Err("bad DER".into());
        }
        if key.len() < len + 4 {
            return Err("key too short".into());
        }
        return Ok(key.split_at(len + 4));
    }
    Err("key too long".into())
}
