/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// The core logic of this module was shamelessly plucked from
// https://github.com/mozkeeler/cert-storage-inspector

use crate::errors::*;
use lmdb::EnvironmentFlags;
use rkv::{Rkv, StoreOptions, Value};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::path::PathBuf;

pub struct CertStorage {
    pub data: HashSet<IssuerSerial>,
}

#[derive(Eq, PartialEq, Hash)]
pub struct IssuerSerial {
    pub issuer_name: String,
    pub serial: String,
}

impl TryFrom<PathBuf> for CertStorage {
    type Error = Error;

    fn try_from(mut db_path: PathBuf) -> Result<Self> {
        let mut revocations = CertStorage {
            data: HashSet::new(),
        };
        let mut builder = Rkv::environment_builder();
        builder.set_max_dbs(2);
        builder.set_flags(EnvironmentFlags::READ_ONLY);
        db_path.push("data.safe.bin");
        let env = Rkv::from_env(&db_path, builder)?;
        let store = env.open_single("cert_storage", StoreOptions::default())?;
        let reader = env.read()?;
        for item in store.iter_start(&reader)? {
            let (key, value) = item?;
            let is = if key.starts_with(&vec![b'i', b's']) && key.len() > 2 {
                decode_revocation(&key[2..key.len()], &value)
            } else {
                None
            };
            match is {
                Some(Ok(issuer_serial)) => {
                    revocations.data.insert(issuer_serial);
                }
                Some(Err(err)) => {
                    Err(err).chain_err(|| "failed to build set from cert_storage")?;
                }
                None => {
                    ();
                }
            };
        }
        Ok(revocations)
    }
}

fn decode_revocation(key: &[u8], value: &Option<Value>) -> Option<Result<IssuerSerial>> {
    match *value {
        Some(Value::I64(i)) if i == 1 => {}
        Some(Value::I64(i)) if i == 0 => return None,
        None => return None,
        Some(_) => return None,
    }
    Some(match split_der_key(key) {
        Ok((part1, part2)) => Ok(IssuerSerial {
            issuer_name: base64::encode(part1),
            serial: base64::encode(part2),
        }),
        Err(e) => Err(e),
    })
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
