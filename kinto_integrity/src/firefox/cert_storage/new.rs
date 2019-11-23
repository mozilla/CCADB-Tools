/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate base64;
extern crate byteorder;
extern crate crossbeam_utils;
#[macro_use]
extern crate log;
extern crate rkv;
extern crate sha2;
extern crate tempfile;
extern crate thin_vec;
extern crate time;

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use crossbeam_utils::atomic::AtomicCell;
use rkv::backend::{BackendEnvironmentBuilder, SafeMode, SafeModeDatabase, SafeModeEnvironment};
use rkv::{StoreError, StoreOptions, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::fs::{create_dir_all, remove_file, File};
use std::io::{BufRead, BufReader};
use std::mem::size_of;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::slice;
use std::str;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};


use thin_vec::ThinVec;

macro_rules! make_key {
    ( $prefix:expr, $( $part:expr ),+ ) => {
        {
            let mut key = $prefix.as_bytes().to_owned();
            $( key.extend_from_slice($part); )+
            key
        }
    }
}

const PREFIX_REV_IS: &str = "is";
const PREFIX_REV_SPK: &str = "spk";
const PREFIX_CRLITE: &str = "crlite";
const PREFIX_SUBJECT: &str = "subject";
const PREFIX_CERT: &str = "cert";
const PREFIX_DATA_TYPE: &str = "datatype";

type Rkv = rkv::Rkv<SafeModeEnvironment>;
type SingleStore = rkv::SingleStore<SafeModeDatabase>;



#[allow(non_camel_case_types, non_snake_case)]

/// `SecurityStateError` is a type to represent errors in accessing or
/// modifying security state.
#[derive(Debug)]
struct SecurityStateError {
    message: String,
}

impl<T: Display> From<T> for SecurityStateError {
    /// Creates a new instance of `SecurityStateError` from something that
    /// implements the `Display` trait.
    fn from(err: T) -> SecurityStateError {
        SecurityStateError {
            message: format!("{}", err),
        }
    }
}

struct EnvAndStore {
    env: Rkv,
    store: SingleStore,
}

/// `SecurityState`
struct SecurityState {
    profile_path: PathBuf,
    env_and_store: Option<EnvAndStore>,
    int_prefs: HashMap<String, u32>,
}

impl SecurityState {
    pub fn new(profile_path: PathBuf) -> Result<SecurityState, SecurityStateError> {
        // Since this gets called on the main thread, we don't actually want to open the DB yet.
        // We do this on-demand later, when we're probably on a certificate verification thread.
        Ok(SecurityState {
            profile_path,
            env_and_store: None,
            int_prefs: HashMap::new(),
        })
    }

    pub fn db_needs_opening(&self) -> bool {
        self.env_and_store.is_none()
    }

    pub fn open_db(&mut self) -> Result<(), SecurityStateError> {
        if self.env_and_store.is_some() {
            return Ok(());
        }

        let store_path = get_store_path(&self.profile_path)?;

        // Open the store in read-write mode to create it (if needed) and migrate data from the old
        // store (if any).
        // If opening initially fails, try to remove and recreate the database. Consumers will
        // repopulate the database as necessary if this happens (see bug 1546361).
        let env = make_env(store_path.as_path()).or_else(|_| {
            remove_db(store_path.as_path())?;
            make_env(store_path.as_path())
        })?;
        let store = env.open_single("cert_storage", StoreOptions::create())?;

        // We already returned early if env_and_store was Some, so this should take the None branch.
        match self.env_and_store.replace(EnvAndStore { env, store }) {
            Some(_) => Err(SecurityStateError::from(
                "env and store already initialized? (did we mess up our threading model?)",
            )),
            None => Ok(()),
        }?;
        Ok(())
    }

    fn read_entry(&self, key: &[u8]) -> Result<Option<i16>, SecurityStateError> {
        let env_and_store = match self.env_and_store.as_ref() {
            Some(env_and_store) => env_and_store,
            None => return Err(SecurityStateError::from("env and store not initialized?")),
        };
        let reader = env_and_store.env.read()?;
        match env_and_store.store.get(&reader, key) {
            Ok(Some(Value::I64(i)))
                if i <= (std::i16::MAX as i64) && i >= (std::i16::MIN as i64) =>
            {
                Ok(Some(i as i16))
            }
            Ok(None) => Ok(None),
            Ok(_) => Err(SecurityStateError::from(
                "Unexpected type when trying to get a Value::I64",
            )),
            Err(_) => Err(SecurityStateError::from(
                "There was a problem getting the value",
            )),
        }
    }

    pub fn get_has_prior_data(&self, data_type: u8) -> Result<bool, SecurityStateError> {
        let env_and_store = match self.env_and_store.as_ref() {
            Some(env_and_store) => env_and_store,
            None => return Err(SecurityStateError::from("env and store not initialized?")),
        };
        let reader = env_and_store.env.read()?;
        match env_and_store
            .store
            .get(&reader, &make_key!(PREFIX_DATA_TYPE, &[data_type]))
        {
            Ok(Some(Value::Bool(true))) => Ok(true),
            Ok(None) => Ok(false),
            Ok(_) => Err(SecurityStateError::from(
                "Unexpected type when trying to get a Value::Bool",
            )),
            Err(_) => Err(SecurityStateError::from(
                "There was a problem getting the value",
            )),
        }
    }

    pub fn set_batch_state(
        &mut self,
        entries: &[(Vec<u8>, i16)],
        typ: u8,
    ) -> Result<(), SecurityStateError> {
        let env_and_store = match self.env_and_store.as_mut() {
            Some(env_and_store) => env_and_store,
            None => return Err(SecurityStateError::from("env and store not initialized?")),
        };
        let mut writer = env_and_store.env.write()?;
        // Make a note that we have prior data of the given type now.
        env_and_store.store.put(
            &mut writer,
            &make_key!(PREFIX_DATA_TYPE, &[typ]),
            &Value::Bool(true),
        )?;

        for entry in entries {
            env_and_store
                .store
                .put(&mut writer, &entry.0, &Value::I64(entry.1 as i64))?;
        }

        writer.commit()?;
        Ok(())
    }

    pub fn pref_seen(&mut self, name: &str, value: u32) {
        self.int_prefs.insert(name.to_owned(), value);
    }

    // To store certificates, we create a Cert out of each given cert, subject, and trust tuple. We
    // hash each certificate with sha-256 to obtain a unique* key for that certificate, and we store
    // the Cert in the database. We also look up or create a CertHashList for the given subject and
    // add the new certificate's hash if it isn't present in the list. If it wasn't present, we
    // write out the updated CertHashList.
    // *By the pigeon-hole principle, there exist collisions for sha-256, so this key is not
    // actually unique. We rely on the assumption that sha-256 is a cryptographically strong hash.
    // If an adversary can find two different certificates with the same sha-256 hash, they can
    // probably forge a sha-256-based signature, so assuming the keys we create here are unique is
    // not a security issue.
    pub fn add_certs(
        &mut self,
        certs: &[(Vec<u8>, Vec<u8>, i16)],
    ) -> Result<(), SecurityStateError> {
        //        let env_and_store = match self.env_and_store.as_mut() {
        //            Some(env_and_store) => env_and_store,
        //            None => return Err(SecurityStateError::from("env and store not initialized?")),
        //        };
        //        let mut writer = env_and_store.env.write()?;
        //        // Make a note that we have prior cert data now.
        //        env_and_store.store.put(
        //            &mut writer,
        //            &make_key!(
        //                PREFIX_DATA_TYPE,
        //                &[nsICertStorage::DATA_TYPE_CERTIFICATE as u8]
        //            ),
        //            &Value::Bool(true),
        //        )?;
        //
        //        for (cert_der, subject, trust) in certs {
        //            let mut digest = Sha256::default();
        //            digest.input(cert_der);
        //            let cert_hash = digest.result();
        //            let cert_key = make_key!(PREFIX_CERT, &cert_hash);
        //            let cert = Cert::new(cert_der, subject, *trust)?;
        //            env_and_store
        //                .store
        //                .put(&mut writer, &cert_key, &Value::Blob(&cert.to_bytes()?))?;
        //            let subject_key = make_key!(PREFIX_SUBJECT, subject);
        //            let empty_vec = Vec::new();
        //            let old_cert_hash_list = match env_and_store.store.get(&writer, &subject_key)? {
        //                Some(Value::Blob(hashes)) => hashes.to_owned(),
        //                Some(_) => empty_vec,
        //                None => empty_vec,
        //            };
        //            let new_cert_hash_list = CertHashList::add(&old_cert_hash_list, &cert_hash)?;
        //            if new_cert_hash_list.len() != old_cert_hash_list.len() {
        //                env_and_store.store.put(
        //                    &mut writer,
        //                    &subject_key,
        //                    &Value::Blob(&new_cert_hash_list),
        //                )?;
        //            }
        //        }
        //
        //        writer.commit()?;
        Ok(())
    }

    // Given a list of certificate sha-256 hashes, we can look up each Cert entry in the database.
    // We use this to find the corresponding subject so we can look up the CertHashList it should
    // appear in. If that list contains the given hash, we remove it and update the CertHashList.
    // Finally we delete the Cert entry.
    pub fn remove_certs_by_hashes(&mut self, hashes: &[Vec<u8>]) -> Result<(), SecurityStateError> {
        let env_and_store = match self.env_and_store.as_mut() {
            Some(env_and_store) => env_and_store,
            None => return Err(SecurityStateError::from("env and store not initialized?")),
        };
        let mut writer = env_and_store.env.write()?;
        let reader = env_and_store.env.read()?;

        for hash in hashes {
            let cert_key = make_key!(PREFIX_CERT, hash);
            if let Some(Value::Blob(cert_bytes)) = env_and_store.store.get(&reader, &cert_key)? {
                if let Ok(cert) = Cert::from_bytes(cert_bytes) {
                    let subject_key = make_key!(PREFIX_SUBJECT, &cert.subject);
                    let empty_vec = Vec::new();
                    // We have to use the writer here to make sure we have an up-to-date view of
                    // the cert hash list.
                    let old_cert_hash_list = match env_and_store.store.get(&writer, &subject_key)? {
                        Some(Value::Blob(hashes)) => hashes.to_owned(),
                        Some(_) => empty_vec,
                        None => empty_vec,
                    };
                    let new_cert_hash_list = CertHashList::remove(&old_cert_hash_list, hash)?;
                    if new_cert_hash_list.len() != old_cert_hash_list.len() {
                        env_and_store.store.put(
                            &mut writer,
                            &subject_key,
                            &Value::Blob(&new_cert_hash_list),
                        )?;
                    }
                }
            }
            match env_and_store.store.delete(&mut writer, &cert_key) {
                Ok(()) => {}
                Err(StoreError::KeyValuePairNotFound) => {}
                Err(e) => return Err(SecurityStateError::from(e)),
            };
        }
        writer.commit()?;
        Ok(())
    }

    // Given a certificate's subject, we look up the corresponding CertHashList. In theory, each
    // hash in that list corresponds to a certificate with the given subject, so we look up each of
    // these (assuming the database is consistent and contains them) and add them to the given list.
    // If we encounter an inconsistency, we continue looking as best we can.
    pub fn find_certs_by_subject(
        &self,
        subject: &[u8],
        certs: &mut ThinVec<ThinVec<u8>>,
    ) -> Result<(), SecurityStateError> {
        let env_and_store = match self.env_and_store.as_ref() {
            Some(env_and_store) => env_and_store,
            None => return Err(SecurityStateError::from("env and store not initialized?")),
        };
        let reader = env_and_store.env.read()?;
        certs.clear();
        let subject_key = make_key!(PREFIX_SUBJECT, subject);
        let empty_vec = Vec::new();
        let cert_hash_list_bytes = match env_and_store.store.get(&reader, &subject_key)? {
            Some(Value::Blob(hashes)) => hashes,
            Some(_) => &empty_vec,
            None => &empty_vec,
        };
        let cert_hash_list = CertHashList::new(cert_hash_list_bytes)?;
        for cert_hash in cert_hash_list.into_iter() {
            let cert_key = make_key!(PREFIX_CERT, cert_hash);
            // If there's some inconsistency, we don't want to fail the whole operation - just go
            // for best effort and find as many certificates as we can.
            if let Some(Value::Blob(cert_bytes)) = env_and_store.store.get(&reader, &cert_key)? {
                if let Ok(cert) = Cert::from_bytes(cert_bytes) {
                    let mut thin_vec_cert = ThinVec::with_capacity(cert.der.len());
                    thin_vec_cert.extend_from_slice(&cert.der);
                    certs.push(thin_vec_cert);
                }
            }
        }
        Ok(())
    }
}

const CERT_SERIALIZATION_VERSION_1: u8 = 1;

// A Cert consists of its DER encoding, its DER-encoded subject, and its trust (currently
// nsICertStorage::TRUST_INHERIT, but in the future nsICertStorage::TRUST_ANCHOR may also be used).
// The length of each encoding must be representable by a u16 (so 65535 bytes is the longest a
// certificate can be).
struct Cert<'a> {
    der: &'a [u8],
    subject: &'a [u8],
    trust: i16,
}

impl<'a> Cert<'a> {
    fn new(der: &'a [u8], subject: &'a [u8], trust: i16) -> Result<Cert<'a>, SecurityStateError> {
        if der.len() > u16::max as usize {
            return Err(SecurityStateError::from("certificate is too long"));
        }
        if subject.len() > u16::max as usize {
            return Err(SecurityStateError::from("subject is too long"));
        }
        Ok(Cert {
            der,
            subject,
            trust,
        })
    }

    fn from_bytes(encoded: &'a [u8]) -> Result<Cert<'a>, SecurityStateError> {
        if encoded.len() < size_of::<u8>() {
            return Err(SecurityStateError::from("invalid Cert: no version?"));
        }
        let (mut version, rest) = encoded.split_at(size_of::<u8>());
        let version = version.read_u8()?;
        if version != CERT_SERIALIZATION_VERSION_1 {
            return Err(SecurityStateError::from("invalid Cert: unexpected version"));
        }

        if rest.len() < size_of::<u16>() {
            return Err(SecurityStateError::from("invalid Cert: no der len?"));
        }
        let (mut der_len, rest) = rest.split_at(size_of::<u16>());
        let der_len = der_len.read_u16::<NetworkEndian>()? as usize;
        if rest.len() < der_len {
            return Err(SecurityStateError::from("invalid Cert: no der?"));
        }
        let (der, rest) = rest.split_at(der_len);

        if rest.len() < size_of::<u16>() {
            return Err(SecurityStateError::from("invalid Cert: no subject len?"));
        }
        let (mut subject_len, rest) = rest.split_at(size_of::<u16>());
        let subject_len = subject_len.read_u16::<NetworkEndian>()? as usize;
        if rest.len() < subject_len {
            return Err(SecurityStateError::from("invalid Cert: no subject?"));
        }
        let (subject, mut rest) = rest.split_at(subject_len);

        if rest.len() < size_of::<i16>() {
            return Err(SecurityStateError::from("invalid Cert: no trust?"));
        }
        let trust = rest.read_i16::<NetworkEndian>()?;
        if rest.len() > 0 {
            return Err(SecurityStateError::from("invalid Cert: trailing data?"));
        }

        Ok(Cert {
            der,
            subject,
            trust,
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, SecurityStateError> {
        let mut bytes = Vec::with_capacity(
            size_of::<u8>()
                + size_of::<u16>()
                + self.der.len()
                + size_of::<u16>()
                + self.subject.len()
                + size_of::<i16>(),
        );
        bytes.write_u8(CERT_SERIALIZATION_VERSION_1)?;
        if self.der.len() > u16::max as usize {
            return Err(SecurityStateError::from("certificate is too long"));
        }
        bytes.write_u16::<NetworkEndian>(self.der.len() as u16)?;
        bytes.extend_from_slice(&self.der);
        if self.subject.len() > u16::max as usize {
            return Err(SecurityStateError::from("subject is too long"));
        }
        bytes.write_u16::<NetworkEndian>(self.subject.len() as u16)?;
        bytes.extend_from_slice(&self.subject);
        bytes.write_i16::<NetworkEndian>(self.trust)?;
        Ok(bytes)
    }
}

// A CertHashList is a list of sha-256 hashes of DER-encoded certificates.
struct CertHashList<'a> {
    hashes: Vec<&'a [u8]>,
}

impl<'a> CertHashList<'a> {
    fn new(hashes_bytes: &'a [u8]) -> Result<CertHashList<'a>, SecurityStateError> {
        if hashes_bytes.len() % Sha256::output_size() != 0 {
            return Err(SecurityStateError::from(
                "unexpected length for cert hash list",
            ));
        }
        let mut hashes = Vec::with_capacity(hashes_bytes.len() / Sha256::output_size());
        for hash in hashes_bytes.chunks_exact(Sha256::output_size()) {
            hashes.push(hash);
        }
        Ok(CertHashList { hashes })
    }

    fn add(hashes_bytes: &[u8], new_hash: &[u8]) -> Result<Vec<u8>, SecurityStateError> {
        if hashes_bytes.len() % Sha256::output_size() != 0 {
            return Err(SecurityStateError::from(
                "unexpected length for cert hash list",
            ));
        }
        if new_hash.len() != Sha256::output_size() {
            return Err(SecurityStateError::from("unexpected cert hash length"));
        }
        for hash in hashes_bytes.chunks_exact(Sha256::output_size()) {
            if hash == new_hash {
                return Ok(hashes_bytes.to_owned());
            }
        }
        let mut combined = hashes_bytes.to_owned();
        combined.extend_from_slice(new_hash);
        Ok(combined)
    }

    fn remove(hashes_bytes: &[u8], cert_hash: &[u8]) -> Result<Vec<u8>, SecurityStateError> {
        if hashes_bytes.len() % Sha256::output_size() != 0 {
            return Err(SecurityStateError::from(
                "unexpected length for cert hash list",
            ));
        }
        if cert_hash.len() != Sha256::output_size() {
            return Err(SecurityStateError::from("unexpected cert hash length"));
        }
        let mut result = Vec::with_capacity(hashes_bytes.len());
        for hash in hashes_bytes.chunks_exact(Sha256::output_size()) {
            if hash != cert_hash {
                result.extend_from_slice(hash);
            }
        }
        Ok(result)
    }
}

impl<'a> IntoIterator for CertHashList<'a> {
    type Item = &'a [u8];
    type IntoIter = std::vec::IntoIter<&'a [u8]>;

    fn into_iter(self) -> Self::IntoIter {
        self.hashes.into_iter()
    }
}

fn get_store_path(profile_path: &PathBuf) -> Result<PathBuf, SecurityStateError> {
    let mut store_path = profile_path.clone();
    store_path.push("security_state");
    create_dir_all(store_path.as_path())?;
    Ok(store_path)
}

fn make_env(path: &Path) -> Result<Rkv, SecurityStateError> {
    let mut builder = Rkv::environment_builder::<SafeMode>();
    builder.set_max_dbs(2);
    builder.set_map_size(16777216); // 16MB
                                    // Bug 1595004: Migrate databases between backends in the future,
                                    // and handle 32 and 64 bit architectures in case of LMDB.
    Rkv::from_builder(path, builder).map_err(SecurityStateError::from)
}

fn unconditionally_remove_file(path: &Path) -> Result<(), SecurityStateError> {
    match remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(SecurityStateError::from(e)),
        },
    }
}

fn remove_db(path: &Path) -> Result<(), SecurityStateError> {
    let db = path.join("data.mdb");
    unconditionally_remove_file(&db)?;
    let lock = path.join("lock.mdb");
    unconditionally_remove_file(&lock)?;
    Ok(())
}

struct InitCertStorage {
    security_state: Arc<RwLock<SecurityState>>,
}
