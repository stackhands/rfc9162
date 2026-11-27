//! A generic append-only ledger of caller-supplied records.
//!
//! Each record is one canonical JSON line: object keys sorted by their
//! UTF-8 bytes, no whitespace outside strings, integers only. [`seal`]
//! writes `index` and `id` around the caller's object and leaves `sig` out
//! of the id. The line's bytes, without a newline, are the leaf. A
//! [`SignedHead`] is the size and root, signed with Ed25519 under
//! [`DOMAIN`].
//!
//! The lines are entries of a [`crate::Store`]. Append, find and the
//! inclusion path are that store's; the leaf hash and the signed bytes are
//! [`rfc9162`]'s. This module does not keep a second tree, run file or tile
//! format. [`crate::Sidecar`] is the project-tree log on the same store: a
//! ledger record is not a path change, so the sidecar's blob names and
//! checkpoint notes are not copied here.
//!
//! `id`, `index` and `sig` belong to the ledger. A caller's record is the
//! other fields. The signing key is a path the signer passes in. A key
//! inside the log directory, or a key with a second hard link, is refused,
//! so the key never travels with the log.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::ser::{
    SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant, Serializer,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use rfc9162_tiles::TileStore;

use crate::store::Store;
use crate::{AuthenticatedLog, Keys, Located};

/// The name a head signature covers, so a head of this log is not a head of
/// any other log that signs RFC 9162 heads.
pub const DOMAIN: &str = "rfc9162-log-ledger-v1";

/// Why a ledger call did not go through.
#[derive(Debug)]
pub enum Error {
    /// A record, line, head or key is not in the ledger's form.
    Format(String),
    /// The store underneath could not answer.
    Log(crate::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(text) => f.write_str(text),
            Self::Log(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Log(error) => Some(error),
            Self::Format(_) => None,
        }
    }
}

impl From<crate::Error> for Error {
    fn from(error: crate::Error) -> Self {
        Self::Log(error)
    }
}

impl From<rfc9162_tiles::Error> for Error {
    fn from(error: rfc9162_tiles::Error) -> Self {
        Self::Log(crate::Error::from(error))
    }
}

/// The canonical JSON of `value`: object keys sorted by their UTF-8 bytes,
/// no whitespace outside strings, strings escaped as `serde_json` writes
/// them. A number that is not an integer is refused, because two writers
/// can print the same float two ways.
pub fn canonical(value: &Value) -> Result<String, Error> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), Error> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => {
            if number.is_f64() {
                return Err(Error::Format(format!(
                    "records hold integers only, not {number}"
                )));
            }
            out.push_str(&number.to_string());
        }
        Value::String(text) => {
            out.push_str(&serde_json::to_string(text).map_err(json_error)?);
        }
        Value::Array(items) => {
            out.push('[');
            for (at, item) in items.iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (at, key) in keys.into_iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).map_err(json_error)?);
                out.push(':');
                write_canonical(&map[key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn json_error(error: serde_json::Error) -> Error {
    Error::Format(format!("record is not JSON: {error}"))
}

/// The record `id`: SHA-256 of the canonical JSON of the record without
/// `id` and `sig`. `index` is inside it, so a record moved to another
/// position has another id.
fn record_id(record: &Map<String, Value>) -> Result<String, Error> {
    let mut body = record.clone();
    body.remove("id");
    body.remove("sig");
    let line = canonical(&Value::Object(body))?;
    Ok(rfc9162::hex(&Sha256::digest(line.as_bytes())))
}

/// One sealed line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Leaf number, which is also the record's `index`.
    pub index: u64,
    /// The record's `id`, lower-case hex.
    pub id: String,
    /// The canonical line, without its newline. Its bytes are the leaf.
    pub line: String,
}

/// Turn a record into the log line for position `index`.
///
/// The record has to serialize as a JSON object. A float anywhere in it,
/// finite or not, is refused. A record that already carries `index` or `id`
/// must carry the values the ledger would write.
/// `id`, when present, is checked and then replaced with the id just
/// computed, so sealing a line that was just parsed yields the same bytes.
pub fn seal<T: Serialize>(record: &T, index: u64) -> Result<Line, Error> {
    reject_floats(record)?;
    let value = serde_json::to_value(record).map_err(json_error)?;
    let Value::Object(mut map) = value else {
        return Err(Error::Format("a ledger record is a JSON object".into()));
    };
    if let Some(given) = map.get("index") {
        if given.as_u64() != Some(index) {
            return Err(Error::Format(format!(
                "record says index {given}, but it would be line {index}"
            )));
        }
    }
    map.insert("index".to_string(), Value::from(index));
    let given_id = map.remove("id");
    let id = record_id(&map)?;
    if let Some(given) = given_id {
        if given.as_str() != Some(id.as_str()) {
            return Err(Error::Format(format!(
                "record says id {given}, but it hashes to {id}"
            )));
        }
    }
    map.insert("id".to_string(), Value::from(id.clone()));
    let line = canonical(&Value::Object(map))?;
    Ok(Line { index, id, line })
}

/// Refuses every `f32` and `f64` in `record`.
///
/// `serde_json::to_value` turns `NaN` and infinity into null, and a nested
/// value is serialized the same way, so [`write_canonical`] never sees the
/// original float. This walk rejects the float before a line exists.
fn reject_floats<T: Serialize + ?Sized>(record: &T) -> Result<(), Error> {
    record
        .serialize(RejectFloat)
        .map_err(|seen| Error::Format(seen.0))
}

/// Why a float was seen, in the same words [`write_canonical`] uses.
#[derive(Debug)]
struct FloatSeen(String);

impl std::fmt::Display for FloatSeen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FloatSeen {}

impl serde::ser::Error for FloatSeen {
    fn custom<T: std::fmt::Display>(message: T) -> Self {
        Self(message.to_string())
    }
}

fn seen_float(number: f64) -> FloatSeen {
    let shown = serde_json::Number::from_f64(number)
        .map(|number| number.to_string())
        .unwrap_or_else(|| number.to_string());
    FloatSeen(format!("records hold integers only, not {shown}"))
}

/// A walk that accepts every JSON value except a float.
struct RejectFloat;

impl RejectFloat {
    fn allow(self) -> Result<(), FloatSeen> {
        Ok(())
    }

    fn walk<T: ?Sized + Serialize>(self, value: &T) -> Result<(), FloatSeen> {
        value.serialize(self)
    }
}

impl Serializer for RejectFloat {
    type Ok = ();
    type Error = FloatSeen;

    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, _v: bool) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_i8(self, _v: i8) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_i16(self, _v: i16) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_i32(self, _v: i32) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_i64(self, _v: i64) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_i128(self, _v: i128) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_u8(self, _v: u8) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_u16(self, _v: u16) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_u32(self, _v: u32) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_u64(self, _v: u64) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_u128(self, _v: u128) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_f32(self, number: f32) -> Result<(), FloatSeen> {
        Err(seen_float(f64::from(number)))
    }

    fn serialize_f64(self, number: f64) -> Result<(), FloatSeen> {
        Err(seen_float(number))
    }

    fn serialize_char(self, _v: char) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_str(self, _v: &str) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_bytes(self, _v: &[u8]) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_none(self) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_some<T>(self, value: &T) -> Result<(), FloatSeen>
    where
        T: ?Sized + Serialize,
    {
        self.walk(value)
    }

    fn serialize_unit(self) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<(), FloatSeen> {
        self.allow()
    }

    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<(), FloatSeen>
    where
        T: ?Sized + Serialize,
    {
        self.walk(value)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<(), FloatSeen>
    where
        T: ?Sized + Serialize,
    {
        self.walk(value)
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, FloatSeen> {
        Ok(RejectFloat)
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, FloatSeen> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, FloatSeen> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, FloatSeen> {
        self.serialize_seq(Some(len))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, FloatSeen> {
        Ok(RejectFloat)
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, FloatSeen> {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, FloatSeen> {
        self.serialize_map(Some(len))
    }
}

fn walk_child<T: ?Sized + Serialize>(value: &T) -> Result<(), FloatSeen> {
    value.serialize(RejectFloat)
}

impl SerializeSeq for RejectFloat {
    type Ok = ();
    type Error = FloatSeen;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), FloatSeen>
    where
        T: ?Sized + Serialize,
    {
        walk_child(value)
    }

    fn end(self) -> Result<(), FloatSeen> {
        Ok(())
    }
}

impl SerializeTuple for RejectFloat {
    type Ok = ();
    type Error = FloatSeen;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), FloatSeen>
    where
        T: ?Sized + Serialize,
    {
        walk_child(value)
    }

    fn end(self) -> Result<(), FloatSeen> {
        Ok(())
    }
}

impl SerializeTupleStruct for RejectFloat {
    type Ok = ();
    type Error = FloatSeen;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), FloatSeen>
    where
        T: ?Sized + Serialize,
    {
        walk_child(value)
    }

    fn end(self) -> Result<(), FloatSeen> {
        Ok(())
    }
}

impl SerializeTupleVariant for RejectFloat {
    type Ok = ();
    type Error = FloatSeen;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), FloatSeen>
    where
        T: ?Sized + Serialize,
    {
        walk_child(value)
    }

    fn end(self) -> Result<(), FloatSeen> {
        Ok(())
    }
}

impl SerializeMap for RejectFloat {
    type Ok = ();
    type Error = FloatSeen;

    fn serialize_key<T>(&mut self, key: &T) -> Result<(), FloatSeen>
    where
        T: ?Sized + Serialize,
    {
        walk_child(key)
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<(), FloatSeen>
    where
        T: ?Sized + Serialize,
    {
        walk_child(value)
    }

    fn end(self) -> Result<(), FloatSeen> {
        Ok(())
    }
}

impl SerializeStruct for RejectFloat {
    type Ok = ();
    type Error = FloatSeen;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<(), FloatSeen>
    where
        T: ?Sized + Serialize,
    {
        walk_child(value)
    }

    fn end(self) -> Result<(), FloatSeen> {
        Ok(())
    }
}

impl SerializeStructVariant for RejectFloat {
    type Ok = ();
    type Error = FloatSeen;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<(), FloatSeen>
    where
        T: ?Sized + Serialize,
    {
        walk_child(value)
    }

    fn end(self) -> Result<(), FloatSeen> {
        Ok(())
    }
}

/// A line parsed back into the caller's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<T> {
    /// Leaf number.
    pub index: u64,
    /// The record's `id`.
    pub id: String,
    /// The canonical line, without its newline.
    pub line: String,
    /// The caller's fields: `id`, `index` and `sig` are not part of it.
    pub record: T,
}

/// Parse one canonical line at `index`.
///
/// The line has to be canonical JSON, its `index` has to be `index`, and
/// its `id` has to be the id [`seal`] would write.
pub fn parse_line<T: DeserializeOwned>(line: &str, index: u64) -> Result<Parsed<T>, Error> {
    let value: Value = serde_json::from_str(line).map_err(json_error)?;
    let Value::Object(map) = value else {
        return Err(Error::Format("not a JSON object".into()));
    };
    if canonical(&Value::Object(map.clone()))? != line {
        return Err(Error::Format("not in canonical form".into()));
    }
    if map.get("index").and_then(Value::as_u64) != Some(index) {
        return Err(Error::Format(format!(
            "index is {:?}, not {index}",
            map.get("index")
        )));
    }
    let id = record_id(&map)?;
    if map.get("id").and_then(Value::as_str) != Some(id.as_str()) {
        return Err(Error::Format(format!(
            "id is {:?}; the record hashes to {id}",
            map.get("id")
        )));
    }
    Ok(Parsed {
        index,
        id,
        line: line.to_string(),
        record: body_record(&map)?,
    })
}

fn body_record<T: DeserializeOwned>(map: &Map<String, Value>) -> Result<T, Error> {
    let mut body = map.clone();
    body.remove("id");
    body.remove("index");
    body.remove("sig");
    serde_json::from_value(Value::Object(body)).map_err(json_error)
}

/// A signed tree head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHead {
    /// Always [`DOMAIN`].
    pub domain: String,
    /// Number of records the root covers.
    pub size: usize,
    /// Merkle root over the first `size` leaves, lower-case hex.
    pub root: String,
    /// Time the head was signed, as the caller supplied it.
    pub ts: String,
    /// Ed25519 public key of the signer, lower-case hex.
    pub public_key: String,
    /// Ed25519 signature over [`SignedHead::material`], lower-case hex.
    pub signature: String,
}

impl SignedHead {
    /// The bytes the signature covers: [`rfc9162::Head::material`] under
    /// [`DOMAIN`], a tab, and `ts`.
    #[must_use]
    pub fn material(size: usize, root: &str, ts: &str) -> Vec<u8> {
        let head = rfc9162::Head {
            size,
            root: root.to_string(),
        };
        let mut bytes = head.material(DOMAIN);
        bytes.push(b'\t');
        bytes.extend_from_slice(ts.as_bytes());
        bytes
    }

    /// Sign the head over a tree of `size` whose root is `root`.
    #[must_use]
    pub fn sign(size: usize, root: &str, key: &SigningKey, ts: &str) -> Self {
        let signature = key.sign(&Self::material(size, root, ts));
        Self {
            domain: DOMAIN.to_string(),
            size,
            root: root.to_string(),
            ts: ts.to_string(),
            public_key: rfc9162::hex(key.verifying_key().as_bytes()),
            signature: rfc9162::hex(&signature.to_bytes()),
        }
    }

    /// Check the domain, that the signer is `trusted`, and the signature.
    pub fn check(&self, trusted: &VerifyingKey) -> Result<(), Error> {
        if self.domain != DOMAIN {
            return Err(Error::Format(format!(
                "head domain is {:?}, not {DOMAIN}",
                self.domain
            )));
        }
        let signer = rfc9162::hex(trusted.as_bytes());
        if self.public_key != signer {
            return Err(Error::Format(format!(
                "head is signed by {}, not by the trusted key {signer}",
                self.public_key
            )));
        }
        let raw = decode_signature(&self.signature)
            .ok_or_else(|| Error::Format("head signature is not 128 hex characters".into()))?;
        trusted
            .verify_strict(
                &Self::material(self.size, &self.root, &self.ts),
                &Signature::from_bytes(&raw),
            )
            .map_err(|_| Error::Format("head signature does not verify".into()))
    }
}

/// A 64 byte signature from 128 lower-case hex characters.
fn decode_signature(text: &str) -> Option<[u8; 64]> {
    if text.len() != 128 || !text.is_ascii() {
        return None;
    }
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&rfc9162::from_hex(&text[..64])?);
    raw[32..].copy_from_slice(&rfc9162::from_hex(&text[64..])?);
    Some(raw)
}

/// Read an Ed25519 PKCS#8 PEM key and refuse one that sits inside `log_dir`.
///
/// A key with a second hard link is refused on platforms that report link
/// counts: that other name could sit in the log directory, where the path
/// check cannot see it.
pub fn load_signing_key(path: &Path, log_dir: &Path) -> Result<SigningKey, Error> {
    let mut file = File::open(path)
        .map_err(|error| Error::Format(format!("read signing key {}: {error}", path.display())))?;
    let opened = file
        .metadata()
        .map_err(|error| Error::Format(format!("signing key {}: {error}", path.display())))?;
    if !opened.is_file() {
        return Err(Error::Format(format!(
            "signing key {} is not a regular file",
            path.display()
        )));
    }
    let resolved = refuse_key_in_log_dir(path, log_dir)?;
    check_key_file(&opened, &resolved, path)?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| Error::Format(format!("read signing key {}: {error}", path.display())))?;
    SigningKey::from_pkcs8_pem(&text).map_err(|error| {
        Error::Format(format!(
            "signing key {} is not Ed25519 PKCS#8 PEM: {error}",
            path.display()
        ))
    })
}

/// The resolved key path, or an error when that path is inside `log_dir`.
fn refuse_key_in_log_dir(key: &Path, log_dir: &Path) -> Result<PathBuf, Error> {
    let key = key
        .canonicalize()
        .map_err(|error| Error::Format(format!("signing key {}: {error}", key.display())))?;
    let directory = log_dir
        .canonicalize()
        .map_err(|error| Error::Format(format!("log directory {}: {error}", log_dir.display())))?;
    if key.starts_with(&directory) {
        return Err(Error::Format(format!(
            "signing key {} is inside the log directory {}; keep the key off the log's tree",
            key.display(),
            directory.display()
        )));
    }
    Ok(key)
}

/// Refuse a second hard link, and a key file that changes while it is read.
/// Both need a device and inode, which Unix reports.
#[cfg(unix)]
fn check_key_file(opened: &std::fs::Metadata, resolved: &Path, path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt;
    if opened.nlink() != 1 {
        return Err(Error::Format(format!(
            "signing key {} has {} hard links; a key with another name could travel with the log",
            path.display(),
            opened.nlink()
        )));
    }
    let current = std::fs::metadata(resolved)
        .map_err(|error| Error::Format(format!("signing key {}: {error}", path.display())))?;
    if (current.dev(), current.ino()) != (opened.dev(), opened.ino()) {
        return Err(Error::Format(format!(
            "signing key {} changed while it was read",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_file(
    _opened: &std::fs::Metadata,
    _resolved: &Path,
    _path: &Path,
) -> Result<(), Error> {
    Ok(())
}

/// One record a find returned, with the proof the store built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found<T> {
    /// Leaf number.
    pub index: u64,
    /// The record's `id`.
    pub id: String,
    /// The caller's record.
    pub record: T,
    /// The entry's inclusion path, and the run's when the entry is sealed.
    pub located: Located,
}

/// A ledger of canonical lines stored in an [`crate::Store`].
pub struct Ledger<S: TileStore> {
    store: Store<S>,
}

impl<S: TileStore> Ledger<S> {
    /// Opens the ledger on `store` with the caller's lookup keys.
    ///
    /// `keys` sees each canonical line. The store also indexes the line's
    /// own hash, as it does for every entry.
    pub fn open(store: S, keys: Keys) -> Result<Self, Error> {
        Ok(Self {
            store: Store::open(store, keys)?,
        })
    }

    /// The number of lines in the log.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.store.size()
    }

    /// The root of the log.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.store.root()
    }

    /// Seal `record` at the next index and append that line.
    pub fn append<T: Serialize>(&mut self, record: &T) -> Result<Line, Error> {
        let line = seal(record, self.store.size())?;
        self.store.append(line.line.as_bytes())?;
        Ok(line)
    }

    /// Sign the current tree.
    pub fn sign(&self, key: &SigningKey, ts: &str) -> Result<SignedHead, Error> {
        let size = usize::try_from(self.store.size())
            .map_err(|_| Error::Format("tree size does not fit".into()))?;
        Ok(SignedHead::sign(
            size,
            &rfc9162::hex(&self.store.root()),
            key,
            ts,
        ))
    }

    /// Read the key at `key`, refusing one stored inside `log_dir`, and
    /// sign the current tree.
    pub fn sign_with_key(&self, key: &Path, log_dir: &Path, ts: &str) -> Result<SignedHead, Error> {
        let key = load_signing_key(key, log_dir)?;
        self.sign(&key, ts)
    }

    /// Check `head` against `trusted` and against every line in the log.
    ///
    /// A line whose bytes no longer hash to the leaf the tree committed to,
    /// or a line that is no longer the canonical record, fails.
    pub fn verify(&self, head: &SignedHead, trusted: &VerifyingKey) -> Result<(), Error> {
        head.check(trusted)?;
        let size = self.store.size();
        let head_size =
            u64::try_from(head.size).map_err(|_| Error::Format("head size does not fit".into()))?;
        if size != head_size {
            return Err(Error::Format(format!(
                "head covers {} records but the log has {size}",
                head.size
            )));
        }
        let view = self.store.index()?;
        let mut leaves = Vec::with_capacity(head.size);
        for at in 0..size {
            let bytes = view
                .reader()
                .get(at)?
                .ok_or_else(|| Error::Format(format!("log has no entry {at}")))?;
            let line = std::str::from_utf8(&bytes)
                .map_err(|_| Error::Format(format!("entry {at} is not UTF-8")))?;
            let parsed = parse_line::<Value>(line, at)?;
            leaves.push(rfc9162::leaf_hash(parsed.line.as_bytes()));
        }
        let got = rfc9162::Head::over(&leaves);
        if got.size != head.size || got.root != head.root {
            return Err(Error::Format(format!(
                "log root {} does not match the head {}",
                got.root, head.root
            )));
        }
        Ok(())
    }

    /// Records carrying `key`, each with the inclusion proof the store
    /// returned. The proof is checked against this tree before it is
    /// returned.
    pub fn find<T: DeserializeOwned>(&self, key: &[u8]) -> Result<Vec<Found<T>>, Error> {
        let located = self.store.find(key)?;
        let view = self.store.index()?;
        let root = rfc9162::hex(&self.store.root());
        let tree_size = usize::try_from(self.store.size())
            .map_err(|_| Error::Format("tree size does not fit".into()))?;
        let mut found = Vec::with_capacity(located.len());
        for hit in located {
            let at = hit.entry.index;
            let bytes = view
                .reader()
                .get(at)?
                .ok_or_else(|| Error::Format(format!("log has no entry {at}")))?;
            let index =
                usize::try_from(at).map_err(|_| Error::Format("index does not fit".into()))?;
            let proof_size = usize::try_from(hit.entry.tree_size)
                .map_err(|_| Error::Format("tree size does not fit".into()))?;
            if proof_size != tree_size
                || !rfc9162::verify_inclusion(
                    &rfc9162::leaf_hash(&bytes),
                    index,
                    proof_size,
                    &hit.entry.path,
                    &root,
                )
            {
                return Err(Error::Format(format!(
                    "entry {at} is not in the tree of size {tree_size} root {root}"
                )));
            }
            let line = std::str::from_utf8(&bytes)
                .map_err(|_| Error::Format(format!("entry {at} is not UTF-8")))?;
            let parsed = parse_line(line, at)?;
            found.push(Found {
                index: parsed.index,
                id: parsed.id,
                record: parsed.record,
                located: hit,
            });
        }
        Ok(found)
    }
}
