//! One behaviour each for the generic ledger.

use std::sync::Arc;

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use rfc9162_log::ledger::{self, Ledger};
use rfc9162_tiles::layout::{entries_path, Layout};
use rfc9162_tiles::{MemoryStore, TileStore};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const TS: &str = "2026-11-27T00:00:00Z";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Item {
    name: String,
    n: u32,
}

fn name_keys(entry: &[u8]) -> Vec<Vec<u8>> {
    let Ok(value) = serde_json::from_slice::<Value>(entry) else {
        return Vec::new();
    };
    match value.get("name").and_then(Value::as_str) {
        Some(name) => vec![format!("name={name}").into_bytes()],
        None => Vec::new(),
    }
}

fn open() -> Ledger<MemoryStore> {
    Ledger::open(MemoryStore::new(), Arc::new(name_keys)).unwrap()
}

#[test]
fn a_canonical_line_round_trips_byte_for_byte() {
    let loose: Value =
        serde_json::from_str(r#"{ "n" : 2, "name" : "a\nb", "ok" : true }"#).unwrap();
    let other = serde_json::json!({"ok": true, "name": "a\nb", "n": 2});
    let line = ledger::seal(&loose, 7).unwrap();
    let again = ledger::seal(&other, 7).unwrap();
    assert_eq!(again.line.as_bytes(), line.line.as_bytes());
    assert!(!line.line.contains('\n'));
    let parsed: Value = serde_json::from_str(&line.line).unwrap();
    assert_eq!(
        ledger::canonical(&parsed).unwrap().as_bytes(),
        line.line.as_bytes()
    );
    assert_eq!(
        ledger::seal(&parsed, 7).unwrap().line.as_bytes(),
        line.line.as_bytes()
    );
    assert!(ledger::canonical(&serde_json::json!({"n": 1.5})).is_err());
}

#[test]
fn a_tampered_line_fails_verify() {
    let store = MemoryStore::new();
    let eyes = store.clone();
    let mut ledger = Ledger::open(store, Arc::new(name_keys)).unwrap();
    let key = SigningKey::from_bytes(&[4u8; 32]);
    ledger
        .append(&Item {
            name: "one".into(),
            n: 1,
        })
        .unwrap();
    let head = ledger.sign(&key, TS).unwrap();
    ledger.verify(&head, &key.verifying_key()).unwrap();

    let layout = Layout::new(ledger.size());
    let path = entries_path(layout.full_bundles(), layout.partial_bundle_width());
    let mut bytes = eyes.get(&path).unwrap().expect("partial bundle");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    eyes.put(&path, &bytes).unwrap();

    assert!(ledger.verify(&head, &key.verifying_key()).is_err());
}

#[test]
fn the_signed_head_verifies_and_fails_when_one_byte_is_flipped() {
    let mut ledger = open();
    ledger
        .append(&Item {
            name: "one".into(),
            n: 1,
        })
        .unwrap();
    let key = SigningKey::from_bytes(&[5u8; 32]);
    let head = ledger.sign(&key, TS).unwrap();
    head.check(&key.verifying_key()).unwrap();

    let mut flipped = head.clone();
    flipped.signature = flip_one_signature_byte(&head.signature);
    assert!(flipped.check(&key.verifying_key()).is_err());
}

fn flip_one_signature_byte(signature: &str) -> String {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&rfc9162::from_hex(&signature[..64]).unwrap());
    bytes[32..].copy_from_slice(&rfc9162::from_hex(&signature[64..]).unwrap());
    bytes[0] ^= 0x01;
    rfc9162::hex(&bytes)
}

#[test]
fn a_key_inside_the_log_dir_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let log_dir = root.path().join("log");
    std::fs::create_dir(&log_dir).unwrap();
    let pem = SigningKey::from_bytes(&[3u8; 32])
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap();
    let inside = log_dir.join("key.pem");
    std::fs::write(&inside, pem.as_bytes()).unwrap();
    let ledger = open();
    let error = ledger.sign_with_key(&inside, &log_dir, TS).unwrap_err();
    assert!(
        error.to_string().contains("inside the log directory"),
        "{error}"
    );

    let outside = root.path().join("key.pem");
    std::fs::write(&outside, pem.as_bytes()).unwrap();
    ledger.sign_with_key(&outside, &log_dir, TS).unwrap();
}

#[test]
fn find_returns_the_record_and_its_inclusion_proof() {
    let mut ledger = open();
    ledger
        .append(&Item {
            name: "alpha".into(),
            n: 1,
        })
        .unwrap();
    ledger
        .append(&Item {
            name: "beta".into(),
            n: 2,
        })
        .unwrap();
    let found = ledger.find::<Item>(b"name=beta").unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0].record,
        Item {
            name: "beta".into(),
            n: 2,
        }
    );
    assert_eq!(found[0].index, 1);
    assert!(!found[0].located.entry.path.is_empty());

    let line = ledger::seal(&found[0].record, found[0].index).unwrap();
    assert_eq!(line.id, found[0].id);
    assert!(rfc9162::verify_inclusion(
        &rfc9162::leaf_hash(line.line.as_bytes()),
        found[0].index as usize,
        found[0].located.entry.tree_size as usize,
        &found[0].located.entry.path,
        &rfc9162::hex(&ledger.root()),
    ));
}
