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
//! ```
//!
//! Status 0 is done, 2 is a command line this binary does not take, 1 is a
//! store or a proof that did not answer. The command line is checked before
//! the pack is opened, so one it does not take leaves nothing at `DIR`.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::SigningKey;
use rfc9162_log::{Op, Sidecar};
use rfc9162_tiles::{Checkpoint, Note, PackStore, Signer, Verifier};

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
}

fn usage(what: &str) -> ExitCode {
    eprintln!("rfc9162-sidecar: {what}");
    eprintln!("usage: rfc9162-sidecar COMMAND --dir DIR [...]; commands: init sync snapshot history tree diff blob include");
    ExitCode::from(2)
}

fn parse(argv: Vec<String>) -> Result<Args, String> {
    let mut it = argv.into_iter();
    let name = it.next().ok_or("a command is needed")?;
    let (mut dir, mut key, mut origin, mut note, mut out) = (None, None, None, None, None);
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
        other => return Err(format!("unknown command {other}")),
    };
    Ok(Args {
        dir: dir.ok_or("--dir DIR is needed")?,
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
    let store = open(dir)?;
    let mut sidecar = Sidecar::open(&store).map_err(|e| format!("sidecar: {e}"))?;
    let out = io::stdout();
    let mut out = out.lock();
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
