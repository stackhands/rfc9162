//! The sidecar from the command line: init, sync, snapshot, history, tree,
//! diff, blob and verify over a project directory, with a PEM signing key.

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use rfc9162_tiles::{PackStore, Signer, TileStore};
use std::path::Path;
use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rfc9162-sidecar"))
        .args(args)
        .output()
        .expect("run rfc9162-sidecar")
}

fn ok(output: &Output) -> String {
    assert!(
        output.status.success(),
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).expect("utf8 stdout")
}

fn write(project: &Path, rel: &str, bytes: &[u8]) {
    let path = project.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn a_project_is_synced_snapshotted_and_read_back_from_the_shell() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("etc");
    std::fs::create_dir_all(&project).unwrap();
    let p = project.to_str().unwrap();
    write(&project, "hosts", b"127.0.0.1 localhost\n");
    write(&project, "ssh/sshd_config", b"Port 22\n");
    let key = dir.path().join("sidecar.pem");
    std::fs::write(
        &key,
        SigningKey::from_bytes(&[7u8; 32])
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let k = key.to_str().unwrap();

    assert!(ok(&cli(&["init", "--dir", p])).contains("size 0"));
    let first = ok(&cli(&["sync", "--dir", p, "--meta", "actor=root"]));
    assert!(first.contains("added hosts\n"), "{first}");
    assert!(
        first.contains("synced: 2 added, 0 changed, 0 deleted, 0 unchanged; entries 0..2; size 2"),
        "{first}"
    );
    let snap = ok(&cli(&[
        "snapshot",
        "--dir",
        p,
        "--key",
        k,
        "--origin",
        "example.org/etc",
    ]));
    assert!(
        snap.starts_with("snapshot example.org/etc size 3 root "),
        "{snap}"
    );
    let trusted = Signer::new("example.org/etc", SigningKey::from_bytes(&[7u8; 32]))
        .unwrap()
        .verifier()
        .to_text();
    let verify = ok(&cli(&[
        "verify",
        "--dir",
        p,
        "--trusted",
        trusted.as_str(),
        "--path",
        "ssh/sshd_config",
    ]));
    assert!(verify.contains("verified checkpoint example.org/etc size 3 root "));
    assert!(verify.contains("verified inclusion ssh/sshd_config index 1 op put steps 2"));

    write(&project, "ssh/sshd_config", b"Port 2222\n");
    std::fs::remove_file(project.join("hosts")).unwrap();
    let second = ok(&cli(&["sync", "--dir", p]));
    assert!(
        second.contains("changed ssh/sshd_config\n") && second.contains("deleted hosts\n"),
        "{second}"
    );

    let history = ok(&cli(&["history", "--dir", p, "ssh/sshd_config"]));
    let lines: Vec<&str> = history.lines().collect();
    assert_eq!(lines.len(), 2, "{history}");
    assert!(lines[0].starts_with("1\tput\tssh/sshd_config\t"));
    assert!(lines[1].starts_with("3\tput\tssh/sshd_config\t"));
    let blob = lines[1].split('\t').nth(3).unwrap();
    assert_eq!(ok(&cli(&["blob", "--dir", p, blob])), "Port 2222\n");

    let tree = ok(&cli(&["tree", "--dir", p]));
    assert_eq!(tree.lines().count(), 1, "{tree}");
    assert!(tree.starts_with("ssh/sshd_config\t3\t"));
    let tree_at_two = ok(&cli(&["tree", "--dir", p, "2"]));
    assert_eq!(tree_at_two.lines().count(), 2, "{tree_at_two}");
    let diff = ok(&cli(&["diff", "--dir", p, "3", "5"]));
    assert!(
        diff.contains("3\tput\tssh/sshd_config") && diff.contains("4\tdelete\thosts"),
        "{diff}"
    );

    // Only the pack and its lock sit beside the project.
    let sidecar: Vec<_> = std::fs::read_dir(project.join(".sidecar"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(sidecar, vec!["pack".to_string()]);

    // A command line this binary does not take is status 2.
    assert_eq!(cli(&["tree"]).status.code(), Some(2));
    assert_eq!(cli(&["frobnicate", "--dir", p]).status.code(), Some(2));
    assert_eq!(
        cli(&["blob", "--dir", p, &"0".repeat(64)]).status.code(),
        Some(1)
    );
}

#[test]
fn verify_fails_on_a_tampered_checkpoint_note() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("etc");
    std::fs::create_dir_all(&project).unwrap();
    let p = project.to_str().unwrap();
    write(&project, "hosts", b"127.0.0.1 localhost\n");
    let key = dir.path().join("sidecar.pem");
    std::fs::write(
        &key,
        SigningKey::from_bytes(&[8u8; 32])
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let k = key.to_str().unwrap();
    ok(&cli(&["sync", "--dir", p]));
    ok(&cli(&[
        "snapshot",
        "--dir",
        p,
        "--key",
        k,
        "--origin",
        "example.org/etc",
    ]));
    let trusted = Signer::new("example.org/etc", SigningKey::from_bytes(&[8u8; 32]))
        .unwrap()
        .verifier()
        .to_text();

    {
        let store = PackStore::open(project.join(".sidecar/pack")).unwrap();
        let mut tampered = String::from_utf8(store.get("checkpoint").unwrap().unwrap()).unwrap();
        tampered = tampered.replacen("example.org/etc", "example.org/evil", 1);
        store.put("checkpoint", tampered.as_bytes()).unwrap();
    }

    let output = cli(&["verify", "--dir", p, "--trusted", trusted.as_str()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("signature does not verify"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn verify_fails_on_a_tampered_inclusion_source() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("etc");
    std::fs::create_dir_all(&project).unwrap();
    let p = project.to_str().unwrap();
    write(&project, "ssh/sshd_config", b"Port 22\n");
    let key = dir.path().join("sidecar.pem");
    std::fs::write(
        &key,
        SigningKey::from_bytes(&[9u8; 32])
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let k = key.to_str().unwrap();
    ok(&cli(&["sync", "--dir", p]));
    ok(&cli(&[
        "snapshot",
        "--dir",
        p,
        "--key",
        k,
        "--origin",
        "example.org/etc",
    ]));
    let trusted = Signer::new("example.org/etc", SigningKey::from_bytes(&[9u8; 32]))
        .unwrap()
        .verifier()
        .to_text();

    {
        let store = PackStore::open(project.join(".sidecar/pack")).unwrap();
        let entry_paths = store.list("tile/entries").unwrap();
        let entry_path = entry_paths.first().expect("one bundle path");
        store.put(entry_path, b"not a bundle").unwrap();
    }

    let output = cli(&[
        "verify",
        "--dir",
        p,
        "--trusted",
        trusted.as_str(),
        "--path",
        "ssh/sshd_config",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("verify: read entry")
            || String::from_utf8_lossy(&output.stderr).contains("verify: find ssh/sshd_config"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_command_line_it_does_not_take_is_status_2_and_opens_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let p = project.to_str().unwrap();
    let note = dir.path().join("child.note");
    std::fs::write(&note, "not a note\n").unwrap();
    let n = note.to_str().unwrap();
    let mut wrong = Vec::new();
    for args in [
        vec!["frobnicate", "--dir", p],
        vec!["history", "--dir", p],
        vec!["tree", "--dir", p, "ten"],
        vec!["diff", "--dir", p, "0"],
        vec!["blob", "--dir", p],
        vec!["snapshot", "--dir", p, "--origin", "example.org/etc"],
        vec!["include", "--dir", p, "child", "--note", n],
        vec![
            "include",
            "--dir",
            p,
            "child",
            "--note",
            n,
            "--trusted",
            "nokey",
        ],
    ] {
        let status = cli(&args).status.code();
        let opened = project.join(".sidecar").exists();
        if status != Some(2) || opened {
            wrong.push(format!(
                "{args:?}: status {status:?}, sidecar opened {opened}"
            ));
        }
        let _ = std::fs::remove_dir_all(project.join(".sidecar"));
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn prove_writes_a_proof_that_survives_a_later_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("etc");
    std::fs::create_dir_all(&project).unwrap();
    let p = project.to_str().unwrap();
    write(&project, "hosts", b"127.0.0.1 localhost\n");
    let key = dir.path().join("sidecar.pem");
    std::fs::write(
        &key,
        SigningKey::from_bytes(&[4u8; 32])
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let k = key.to_str().unwrap();
    ok(&cli(&["sync", "--dir", p]));
    ok(&cli(&[
        "snapshot",
        "--dir",
        p,
        "--key",
        k,
        "--origin",
        "example.org/etc",
    ]));
    let trusted = Signer::new("example.org/etc", SigningKey::from_bytes(&[4u8; 32]))
        .unwrap()
        .verifier()
        .to_text();
    let proof_text = ok(&cli(&["prove", "--dir", p, "--path", "hosts"]));
    let proof: serde_json::Value = serde_json::from_str(&proof_text).unwrap();
    assert_eq!(proof["path"], "hosts");
    assert_eq!(proof["op"], "put");
    assert!(proof["inclusion"].as_array().is_some());
    assert!(proof["checkpoint"]
        .as_str()
        .unwrap()
        .contains("example.org/etc"));
    let proof_path = dir.path().join("proof.json");
    std::fs::write(&proof_path, &proof_text).unwrap();
    let hosts = project.join("hosts");
    let checked = ok(&cli(&[
        "verify-proof",
        "--proof",
        proof_path.to_str().unwrap(),
        "--trusted",
        trusted.as_str(),
        "--blob-file",
        hosts.to_str().unwrap(),
    ]));
    assert!(checked.contains("verified proof hosts index "), "{checked}");

    write(&project, "issue", b"later\n");
    ok(&cli(&["sync", "--dir", p]));
    ok(&cli(&[
        "snapshot",
        "--dir",
        p,
        "--key",
        k,
        "--origin",
        "example.org/etc",
    ]));
    let again = ok(&cli(&[
        "verify-proof",
        "--proof",
        proof_path.to_str().unwrap(),
        "--trusted",
        trusted.as_str(),
        "--blob-file",
        hosts.to_str().unwrap(),
    ]));
    assert!(again.contains("verified proof hosts"), "{again}");

    let root = proof["root"].as_str().unwrap();
    let tampered = proof_text.replacen(root, &"0".repeat(root.len()), 1);
    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, tampered).unwrap();
    let output = cli(&[
        "verify-proof",
        "--proof",
        bad.to_str().unwrap(),
        "--trusted",
        trusted.as_str(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");

    let other = dir.path().join("other");
    std::fs::write(&other, b"not the hosts file\n").unwrap();
    let mismatch = cli(&[
        "verify-proof",
        "--proof",
        proof_path.to_str().unwrap(),
        "--trusted",
        trusted.as_str(),
        "--blob-file",
        other.to_str().unwrap(),
    ]);
    assert_eq!(mismatch.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&mismatch.stderr).contains("does not match blob"),
        "{}",
        String::from_utf8_lossy(&mismatch.stderr)
    );

    assert_eq!(cli(&["prove", "--path", "hosts"]).status.code(), Some(2));
    assert_eq!(
        cli(&["verify-proof", "--trusted", trusted.as_str()])
            .status
            .code(),
        Some(2)
    );
}
