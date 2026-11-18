//! `rfc9162-sidecar`: the sidecar from a shell. The sidecar of a project at
//! `DIR` is the pack at `DIR/.sidecar/pack`; every command opens it, takes
//! the writer lock for the moment it runs, and prints one line per thing.
//!
//! ```text
//! rfc9162-sidecar init    --dir DIR
//! rfc9162-sidecar sync    --dir DIR [--skip NAME]... [--meta K=V]...
//! rfc9162-sidecar snapshot --dir DIR --key KEY.pem --origin ORIGIN
//! rfc9162-sidecar history --dir DIR PATH
//! rfc9162-sidecar tree    --dir DIR [SIZE]
//! rfc9162-sidecar diff    --dir DIR FROM TO
//! rfc9162-sidecar blob    --dir DIR HEX [--out FILE]
//! rfc9162-sidecar include --dir DIR PATH --note FILE --trusted KEYLINE... [--meta K=V]...
//! rfc9162-sidecar verify  --dir DIR --trusted KEYLINE... [--path REL_PATH]
//! rfc9162-sidecar prove   --dir DIR --path PATH [--index N]
//! rfc9162-sidecar verify-proof --proof FILE --trusted KEYLINE... [--blob-file FILE]
//! ```
//!
//! Status 0 is done, 2 is a command line this binary does not take, 1 is a
//! store or a proof that did not answer. The command line is checked before
//! the pack is opened, so one it does not take leaves nothing at `DIR`.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sha2::{Digest, Sha256};

use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::SigningKey;
use rfc9162_log::{sidecar::sidecar_keys, store::tiles_keys, Change, Op, Sidecar};
use rfc9162_tiles::{checkpoint, Checkpoint, Note, PackStore, Reader, Signer, TileStore, Verifier};

const SIDECAR_DIR: &str = ".sidecar";

struct Args {
    dir: PathBuf,
    command: Command,
    out: Option<PathBuf>,
    skip: Vec<String>,
    meta: BTreeMap<String, String>,
}

/// A command with the arguments it takes, each checked.
enum Command {
    Init,
    Sync,
    Snapshot {
        key: PathBuf,
        origin: String,
    },
    History {
        path: String,
    },
    Tree {
        size: Option<u64>,
    },
    Diff {
        from: u64,
        to: u64,
    },
    Blob {
        hex: String,
    },
    Include {
        path: String,
        note: PathBuf,
        trusted: Vec<Verifier>,
    },
    Verify {
        trusted: Vec<Verifier>,
        path: Option<String>,
    },
    Prove {
        path: String,
        index: Option<u64>,
    },
    VerifyProof {
        proof: PathBuf,
        trusted: Vec<Verifier>,
        blob_file: Option<PathBuf>,
    },
}

fn usage(what: &str) -> ExitCode {
    eprintln!("rfc9162-sidecar: {what}");
    eprintln!(
        "usage: rfc9162-sidecar COMMAND --dir DIR [...]; commands: init sync snapshot history tree diff blob include verify prove verify-proof"
    );
    ExitCode::from(2)
}

fn parse(argv: Vec<String>) -> Result<Args, String> {
    let mut it = argv.into_iter();
    let name = it.next().ok_or("a command is needed")?;
    let (
        mut dir,
        mut key,
        mut origin,
        mut note,
        mut out,
        mut verify_path,
        mut index,
        mut proof,
        mut blob_file,
    ) = (None, None, None, None, None, None, None, None, None);
    let (mut skip, mut trusted, mut meta, mut rest) =
        (Vec::new(), Vec::new(), BTreeMap::new(), Vec::new());
    while let Some(arg) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match arg.as_str() {
            "--dir" => dir = Some(PathBuf::from(value("--dir")?)),
            "--key" => key = Some(PathBuf::from(value("--key")?)),
            "--origin" => origin = Some(value("--origin")?),
            "--note" => note = Some(PathBuf::from(value("--note")?)),
            "--out" => out = Some(PathBuf::from(value("--out")?)),
            "--path" => verify_path = Some(value("--path")?),
            "--index" => index = Some(value("--index")?),
            "--proof" => proof = Some(PathBuf::from(value("--proof")?)),
            "--blob-file" => blob_file = Some(PathBuf::from(value("--blob-file")?)),
            "--skip" => skip.push(value("--skip")?),
            "--trusted" => trusted.push(value("--trusted")?),
            "--meta" => {
                let pair = value("--meta")?;
                let (k, v) = pair
                    .split_once('=')
                    .ok_or(format!("--meta {pair:?} is not K=V"))?;
                meta.insert(k.to_string(), v.to_string());
            }
            other if other.starts_with("--") => return Err(format!("unknown flag {other}")),
            _ => rest.push(arg),
        }
    }
    let number = |what: &str, text: &str| {
        text.parse::<u64>()
            .map_err(|_| format!("{what} {text:?} is not a number"))
    };
    let command = match name.as_str() {
        "init" => Command::Init,
        "sync" => Command::Sync,
        "snapshot" => Command::Snapshot {
            key: key.ok_or("--key KEY.pem is needed")?,
            origin: origin.ok_or("--origin ORIGIN is needed")?,
        },
        "history" => Command::History {
            path: rest.first().cloned().ok_or("history needs a PATH")?,
        },
        "tree" => Command::Tree {
            size: rest.first().map(|t| number("SIZE", t)).transpose()?,
        },
        "diff" => match rest.as_slice() {
            [from, to, ..] => Command::Diff {
                from: number("FROM", from)?,
                to: number("TO", to)?,
            },
            _ => return Err("diff needs FROM TO".to_string()),
        },
        "blob" => Command::Blob {
            hex: rest.first().cloned().ok_or("blob needs HEX")?,
        },
        "include" => {
            let path = rest.first().cloned().ok_or("include needs a PATH")?;
            let note = note.ok_or("--note FILE is needed")?;
            if trusted.is_empty() {
                return Err("--trusted KEYLINE is needed at least once".to_string());
            }
            let trusted = trusted
                .iter()
                .map(|line| Verifier::parse(line).map_err(|e| format!("--trusted {line:?}: {e}")))
                .collect::<Result<Vec<_>, _>>()?;
            Command::Include {
                path,
                note,
                trusted,
            }
        }
        "verify" => {
            if trusted.is_empty() {
                return Err("--trusted KEYLINE is needed at least once".to_string());
            }
            let trusted = trusted
                .iter()
                .map(|line| Verifier::parse(line).map_err(|e| format!("--trusted {line:?}: {e}")))
                .collect::<Result<Vec<_>, _>>()?;
            Command::Verify {
                trusted,
                path: verify_path,
            }
        }
        "prove" => {
            let path = verify_path
                .or_else(|| rest.first().cloned())
                .ok_or("prove needs --path PATH")?;
            Command::Prove {
                path,
                index: index.as_deref().map(|t| number("INDEX", t)).transpose()?,
            }
        }
        "verify-proof" => {
            let proof = proof.ok_or("--proof FILE is needed")?;
            if trusted.is_empty() {
                return Err("--trusted KEYLINE is needed at least once".to_string());
            }
            let trusted = trusted
                .iter()
                .map(|line| Verifier::parse(line).map_err(|e| format!("--trusted {line:?}: {e}")))
                .collect::<Result<Vec<_>, _>>()?;
            Command::VerifyProof {
                proof,
                trusted,
                blob_file,
            }
        }
        other => return Err(format!("unknown command {other}")),
    };
    let dir = match &command {
        Command::VerifyProof { .. } => dir.unwrap_or_default(),
        _ => dir.ok_or("--dir DIR is needed")?,
    };
    Ok(Args {
        dir,
        command,
        out,
        skip,
        meta,
    })
}

fn open(dir: &Path) -> Result<PackStore, String> {
    let pack = dir.join(SIDECAR_DIR).join("pack");
    PackStore::open(&pack).map_err(|e| format!("open {}: {e}", pack.display()))
}

fn run(args: &Args) -> Result<(), String> {
    let dir = args.dir.as_path();
    let out = io::stdout();
    let mut out = out.lock();
    match &args.command {
        Command::Verify { trusted, path } => {
            return verify(dir, trusted, path.as_deref(), &mut out);
        }
        Command::Prove { path, index } => return prove(dir, path, *index, &mut out),
        Command::VerifyProof {
            proof,
            trusted,
            blob_file,
        } => {
            return verify_proof(proof, trusted, blob_file.as_deref(), &mut out);
        }
        _ => {}
    }
    let store = open(dir)?;
    let mut sidecar = Sidecar::open(&store).map_err(|e| format!("sidecar: {e}"))?;
    match &args.command {
        Command::Init => {
            writeln!(
                out,
                "sidecar at {} size {}",
                dir.join(SIDECAR_DIR).display(),
                sidecar.size()
            )
            .ok();
        }
        Command::Sync => {
            let mut skip: Vec<&str> = vec![SIDECAR_DIR];
            skip.extend(args.skip.iter().map(String::as_str));
            let synced = sidecar
                .sync_dir(dir, &skip, &args.meta)
                .map_err(|e| format!("sync: {e}"))?;
            for path in &synced.added {
                writeln!(out, "added {path}").ok();
            }
            for path in &synced.changed {
                writeln!(out, "changed {path}").ok();
            }
            for path in &synced.deleted {
                writeln!(out, "deleted {path}").ok();
            }
            writeln!(
                out,
                "synced: {} added, {} changed, {} deleted, {} unchanged; entries {}..{}; size {}",
                synced.added.len(),
                synced.changed.len(),
                synced.deleted.len(),
                synced.unchanged,
                synced.entries.start,
                synced.entries.end,
                sidecar.size()
            )
            .ok();
        }
        Command::Snapshot { key, origin } => {
            let signing = SigningKey::read_pkcs8_pem_file(key)
                .map_err(|e| format!("read signing key {}: {e}", key.display()))?;
            let signer = Signer::new(origin, signing).map_err(|e| format!("signer: {e}"))?;
            let note = sidecar
                .snapshot(&signer, origin)
                .map_err(|e| format!("snapshot: {e}"))?;
            let checkpoint =
                Checkpoint::parse(&note.text).map_err(|e| format!("checkpoint: {e}"))?;
            writeln!(
                out,
                "snapshot {} size {} root {}",
                checkpoint.origin,
                checkpoint.size,
                rfc9162::hex(&checkpoint.root)
            )
            .ok();
        }
        Command::History { path } => {
            for found in sidecar.history(path).map_err(|e| format!("history: {e}"))? {
                writeln!(out, "{}", describe(found.index, &found.change)).ok();
            }
        }
        Command::Tree { size } => {
            let size = size.unwrap_or_else(|| sidecar.size());
            for (path, (index, change)) in
                sidecar.tree_at(size).map_err(|e| format!("tree: {e}"))?
            {
                writeln!(
                    out,
                    "{path}\t{index}\t{}\t{}",
                    change.blob.as_deref().unwrap_or("-"),
                    change.size.unwrap_or(0)
                )
                .ok();
            }
        }
        Command::Diff { from, to } => {
            for (index, change) in sidecar.diff(*from, *to).map_err(|e| format!("diff: {e}"))? {
                writeln!(out, "{}", describe(index, &change)).ok();
            }
        }
        Command::Blob { hex } => {
            let bytes = sidecar
                .blob(hex)
                .map_err(|e| format!("blob: {e}"))?
                .ok_or(format!("no blob {hex}"))?;
            match &args.out {
                Some(file) => std::fs::write(file, &bytes)
                    .map_err(|e| format!("write {}: {e}", file.display()))?,
                None => out.write_all(&bytes).map_err(|e| format!("stdout: {e}"))?,
            }
        }
        Command::Include {
            path,
            note: note_path,
            trusted,
        } => {
            let mut text = String::new();
            std::fs::File::open(note_path)
                .and_then(|mut f| f.read_to_string(&mut text))
                .map_err(|e| format!("read {}: {e}", note_path.display()))?;
            let note = Note::parse(&text).map_err(|e| format!("note: {e}"))?;
            let index = sidecar
                .include_checkpoint(path, &note, trusted, args.meta.clone())
                .map_err(|e| format!("include: {e}"))?;
            writeln!(out, "included {path} at {index}").ok();
        }
        Command::Verify { .. } | Command::Prove { .. } | Command::VerifyProof { .. } => {
            unreachable!("verify, prove and verify-proof return early")
        }
    }
    Ok(())
}

fn prove(dir: &Path, path: &str, index: Option<u64>, out: &mut impl Write) -> Result<(), String> {
    let store = open(dir)?;
    let checkpoint_bytes = store
        .get("checkpoint")
        .map_err(|e| format!("prove: read checkpoint: {e}"))?
        .ok_or("prove: no signed checkpoint in sidecar pack".to_string())?;
    let checkpoint_text = String::from_utf8(checkpoint_bytes)
        .map_err(|_| "prove: checkpoint is not UTF-8".to_string())?;
    let note = Note::parse(&checkpoint_text).map_err(|e| format!("prove: note: {e}"))?;
    let checkpoint =
        Checkpoint::parse(&note.text).map_err(|e| format!("prove: checkpoint: {e}"))?;
    let keys = sidecar_keys();
    let reader = Reader::at(&store, checkpoint.size, checkpoint.root, tiles_keys(&keys))
        .map_err(|e| format!("prove: open reader at checkpoint: {e}"))?;
    let key = format!("path={path}");
    let hits = reader
        .find(key.as_bytes())
        .map_err(|e| format!("prove: find {path}: {e}"))?;
    let index = match index {
        Some(index) => {
            if !hits.contains(&index) {
                return Err(format!("prove: index {index} is not an entry for {path}"));
            }
            if index >= checkpoint.size {
                return Err(format!(
                    "prove: index {index} is outside checkpoint size {}",
                    checkpoint.size
                ));
            }
            index
        }
        None => hits
            .iter()
            .copied()
            .filter(|index| *index < checkpoint.size)
            .max()
            .ok_or(format!(
                "prove: no entry for {path} at checkpoint size {}",
                checkpoint.size
            ))?,
    };
    let bytes = reader
        .get(index)
        .map_err(|e| format!("prove: read entry {index}: {e}"))?
        .ok_or(format!("prove: no entry at index {index}"))?;
    let change: Change = serde_json::from_slice(&bytes)
        .map_err(|_| format!("prove: entry {index} is not a sidecar change"))?;
    if change.path != path {
        return Err(format!(
            "prove: entry {index} records {}, not {path}",
            change.path
        ));
    }
    let inclusion = reader
        .inclusion(index)
        .map_err(|e| format!("prove: inclusion {index}: {e}"))?
        .ok_or(format!("prove: no inclusion proof for index {index}"))?;
    let entry =
        String::from_utf8(bytes).map_err(|_| format!("prove: entry {index} is not UTF-8"))?;
    let mut obj = serde_json::Map::new();
    if let Some(blob) = &change.blob {
        obj.insert("blob".into(), serde_json::Value::String(blob.clone()));
    }
    obj.insert(
        "checkpoint".into(),
        serde_json::Value::String(note.to_text()),
    );
    obj.insert("entry".into(), serde_json::Value::String(entry));
    obj.insert(
        "inclusion".into(),
        serde_json::Value::Array(
            inclusion
                .iter()
                .map(|hash| serde_json::Value::String(rfc9162::hex(hash)))
                .collect(),
        ),
    );
    obj.insert("index".into(), serde_json::json!(index));
    obj.insert(
        "op".into(),
        serde_json::Value::String(
            match change.op {
                Op::Put => "put",
                Op::Delete => "delete",
                Op::Checkpoint => "checkpoint",
            }
            .to_string(),
        ),
    );
    obj.insert(
        "origin".into(),
        serde_json::Value::String(checkpoint.origin),
    );
    obj.insert("path".into(), serde_json::Value::String(change.path));
    obj.insert(
        "root".into(),
        serde_json::Value::String(rfc9162::hex(&checkpoint.root)),
    );
    obj.insert("size".into(), serde_json::json!(checkpoint.size));
    let text = serde_json::to_string_pretty(&serde_json::Value::Object(obj))
        .map_err(|e| format!("prove: {e}"))?;
    writeln!(out, "{text}").ok();
    Ok(())
}

fn verify_proof(
    proof: &Path,
    trusted: &[Verifier],
    blob_file: Option<&Path>,
    out: &mut impl Write,
) -> Result<(), String> {
    let text = std::fs::read_to_string(proof)
        .map_err(|e| format!("verify-proof: read {}: {e}", proof.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("verify-proof: {e}"))?;
    let field = |name: &str| {
        value
            .get(name)
            .and_then(|item| item.as_str())
            .map(str::to_string)
            .ok_or(format!("verify-proof: {name} must be a string"))
    };
    let checkpoint_text = field("checkpoint")?;
    let entry = field("entry")?;
    let origin = field("origin")?;
    let path = field("path")?;
    let root = field("root")?;
    let op = field("op")?;
    let number = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or(format!("verify-proof: {name} must be a number"))
    };
    let index = number("index")?;
    let size = number("size")?;
    let note = Note::parse(&checkpoint_text).map_err(|e| format!("verify-proof: note: {e}"))?;
    let signed =
        checkpoint::verify(&note, trusted).map_err(|e| format!("verify-proof: checkpoint: {e}"))?;
    let checkpoint =
        Checkpoint::parse(&note.text).map_err(|e| format!("verify-proof: checkpoint: {e}"))?;
    let root_hex = rfc9162::hex(&checkpoint.root);
    if origin != checkpoint.origin || size != checkpoint.size || root != root_hex {
        return Err(
            "verify-proof: origin, size or root does not match the checkpoint note".to_string(),
        );
    }
    let inclusion = value
        .get("inclusion")
        .and_then(serde_json::Value::as_array)
        .ok_or("verify-proof: inclusion must be an array")?;
    let mut path_hashes = Vec::with_capacity(inclusion.len());
    for hash in inclusion {
        let text = hash
            .as_str()
            .ok_or("verify-proof: an inclusion hash must be a string")?;
        path_hashes.push(rfc9162::from_hex(text).ok_or(format!(
            "verify-proof: inclusion hash {text:?} is not 32 bytes"
        ))?);
    }
    let proves = rfc9162::verify_inclusion(
        &rfc9162::leaf_hash(entry.as_bytes()),
        index as usize,
        size as usize,
        &path_hashes,
        &root_hex,
    );
    if !proves {
        return Err(format!(
            "verify-proof: inclusion for {path} at index {index} does not verify against checkpoint root"
        ));
    }
    let change: Change = serde_json::from_slice(entry.as_bytes())
        .map_err(|_| "verify-proof: entry is not a sidecar change".to_string())?;
    if change.path != path {
        return Err(format!(
            "verify-proof: entry records {}, not {path}",
            change.path
        ));
    }
    let recorded = match change.op {
        Op::Put => "put",
        Op::Delete => "delete",
        Op::Checkpoint => "checkpoint",
    };
    if op != recorded {
        return Err(format!("verify-proof: entry op is {recorded}, not {op}"));
    }
    if let Some(blob) = value.get("blob").and_then(serde_json::Value::as_str) {
        if change.blob.as_deref() != Some(blob) {
            return Err("verify-proof: entry blob does not match the proof".to_string());
        }
    } else if change.blob.is_some() {
        return Err("verify-proof: entry names a blob the proof omits".to_string());
    }
    if let Some(file) = blob_file {
        let blob = value
            .get("blob")
            .and_then(serde_json::Value::as_str)
            .ok_or("verify-proof: --blob-file needs a blob in the proof")?;
        let bytes = std::fs::read(file)
            .map_err(|e| format!("verify-proof: read {}: {e}", file.display()))?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let hex = rfc9162::hex(&digest);
        if hex != blob {
            return Err(format!(
                "verify-proof: {} sha256 {hex} does not match blob {blob}",
                file.display()
            ));
        }
    }
    writeln!(
        out,
        "verified proof {path} index {index} size {size} root {root_hex} by {} trusted key(s)",
        signed.len()
    )
    .ok();
    Ok(())
}

fn verify(
    dir: &Path,
    trusted: &[Verifier],
    path: Option<&str>,
    out: &mut impl Write,
) -> Result<(), String> {
    let store = open(dir)?;
    let checkpoint_bytes = store
        .get("checkpoint")
        .map_err(|e| format!("verify: read checkpoint: {e}"))?
        .ok_or("verify: no signed checkpoint in sidecar pack".to_string())?;
    let checkpoint_text = String::from_utf8(checkpoint_bytes)
        .map_err(|_| "verify: checkpoint is not UTF-8".to_string())?;
    let note = Note::parse(&checkpoint_text).map_err(|e| format!("verify: note: {e}"))?;
    let signed = checkpoint::verify(&note, trusted).map_err(|e| format!("verify: {e}"))?;
    let checkpoint =
        Checkpoint::parse(&note.text).map_err(|e| format!("verify: checkpoint: {e}"))?;
    let root_hex = rfc9162::hex(&checkpoint.root);
    writeln!(
        out,
        "verified checkpoint {} size {} root {} by {} trusted key(s)",
        checkpoint.origin,
        checkpoint.size,
        root_hex,
        signed.len()
    )
    .ok();

    if let Some(path) = path {
        let keys = sidecar_keys();
        let reader = Reader::at(&store, checkpoint.size, checkpoint.root, tiles_keys(&keys))
            .map_err(|e| format!("verify: open reader at checkpoint: {e}"))?;
        let key = format!("path={path}");
        let hits = reader
            .find(key.as_bytes())
            .map_err(|e| format!("verify: find {path}: {e}"))?;
        let index = hits.last().copied().ok_or(format!(
            "verify: no entry for {path} at checkpoint size {}",
            checkpoint.size
        ))?;
        let bytes = reader
            .get(index)
            .map_err(|e| format!("verify: read entry {index}: {e}"))?
            .ok_or(format!("verify: no entry at index {index}"))?;
        let change: Change = serde_json::from_slice(&bytes)
            .map_err(|_| format!("verify: entry {index} is not a sidecar change"))?;
        let inclusion = reader
            .inclusion(index)
            .map_err(|e| format!("verify: inclusion {index}: {e}"))?
            .ok_or(format!("verify: no inclusion proof for index {index}"))?;
        let proves = rfc9162::verify_inclusion(
            &rfc9162::leaf_hash(&bytes),
            index as usize,
            checkpoint.size as usize,
            &inclusion,
            &root_hex,
        );
        if !proves {
            return Err(format!(
                "verify: inclusion for {path} at index {index} does not verify against checkpoint root"
            ));
        }
        writeln!(
            out,
            "verified inclusion {path} index {index} op {} steps {}",
            match change.op {
                Op::Put => "put",
                Op::Delete => "delete",
                Op::Checkpoint => "checkpoint",
            },
            inclusion.len()
        )
        .ok();
    }
    Ok(())
}

fn describe(index: u64, change: &rfc9162_log::Change) -> String {
    let op = match change.op {
        Op::Put => "put",
        Op::Delete => "delete",
        Op::Checkpoint => "checkpoint",
    };
    let mut line = format!("{index}\t{op}\t{}", change.path);
    if let Some(blob) = &change.blob {
        line.push_str(&format!("\t{blob}"));
    }
    if let Some(size) = change.size {
        line.push_str(&format!("\t{size}"));
    }
    if let Some(origin) = &change.origin {
        line.push_str(&format!("\t{origin}"));
    }
    line
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse(argv) {
        Ok(args) => args,
        Err(what) => return usage(&what),
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(what) => {
            eprintln!("rfc9162-sidecar: {what}");
            ExitCode::from(1)
        }
    }
}
