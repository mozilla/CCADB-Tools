/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// The core logic of this module was shamelessly plucked from
// https://github.com/mozkeeler/cert-storage-inspector

use crate::errors;
use lmdb::EnvironmentFlags;
use rkv::{Rkv, StoreOptions, Value};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::path::PathBuf;
use crate::one_crl::Revocation;

pub fn write(db_path: PathBuf, revocation: Revocation) -> errors::Result<()> {
        let mut builder = Rkv::environment_builder();
        builder.set_max_dbs(2);
        let env = Rkv::from_env(&db_path, builder)?;
        let store = env.open_single("cert_storage", StoreOptions::default())?;
        let mut writer = env.write()?;
        store.put(&mut writer, revocation.to_cert_storage(), &Value::I64(1))?;
        writer.commit()?;
        Ok(())
}


//fn decode_revocation(key: &[u8], value: &Option<Value>) -> Option<Result<IssuerSerial>> {
//    match *value {
//        Some(Value::I64(i)) if i == 1 => {}
//        Some(Value::I64(i)) if i == 0 => return None,
//        None => return None,
//        Some(_) => return None,
//    }
//    Some(match split_der_key(key) {
//        Ok((part1, part2)) => Ok(IssuerSerial {
//            issuer_name: base64::encode(part1),
//            serial: base64::encode(part2),
//        }),
//        Err(e) => Err(e),
//    })
//}
//
//fn split_der_key(key: &[u8]) -> Result<(&[u8], &[u8])> {
//    if key.len() < 2 {
//        return Err("key too short to be DER".into());
//    }
//    let first_len_byte = key[1] as usize;
//    if first_len_byte < 0x80 {
//        if key.len() < first_len_byte + 2 {
//            return Err("key too short".into());
//        }
//        return Ok(key.split_at(first_len_byte + 2 as usize));
//    }
//    if first_len_byte == 0x80 {
//        return Err("unsupported ASN.1".into());
//    }
//    if first_len_byte == 0x81 {
//        if key.len() < 3 {
//            return Err("key too short to be DER".into());
//        }
//        let len = key[2] as usize;
//        if len < 0x80 {
//            return Err("bad DER".into());
//        }
//        if key.len() < len + 3 {
//            return Err("key too short".into());
//        }
//        return Ok(key.split_at(len + 3));
//    }
//    if first_len_byte == 0x82 {
//        if key.len() < 4 {
//            return Err("key too short to be DER".into());
//        }
//        let len = (key[2] as usize) << 8 | key[3] as usize;
//        if len < 256 {
//            return Err("bad DER".into());
//        }
//        if key.len() < len + 4 {
//            return Err("key too short".into());
//        }
//        return Ok(key.split_at(len + 4));
//    }
//    Err("key too long".into())
//}
