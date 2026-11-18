# Changelog

Versions follow semver at 0.x: a minor bump is a feature, a patch is a fix.
The crates carry the one workspace version and are released together.

<!-- towncrier release notes start -->

## 0.11.0 (2026-11-17)

### Features

- `rfc9162-sidecar prove` writes a checkpoint and an inclusion proof for one path, and `verify-proof` checks that proof, and an optional blob file, without opening the log.

### Fixes

- A sidecar whose pair count or key length does not fit in its u16 prefix is refused, instead of being written with the length truncated.
  A bundle of more than 256 entries is refused, because the entry offset is one byte.
- The tile split no longer overflows when a tree is wider than 2^63.
  A perfect subtree whose span does not fit in a u64 is refused instead of being accepted or panicking.
- `rfc9162-log`: A seal or compaction retried after its manifest append failed, or after a crash between storing the run file and logging the manifest, logs the run.
  It found its own run file and refused every retry with "a run for that entry range is already stored"; a run file with other bytes for the range is still refused.
- `rfc9162-sidecar`: A command line the binary does not take exits with status 2 and opens nothing: the command and its arguments are checked before `DIR/.sidecar/pack` is opened.
  An unknown command or a missing argument created the pack, and a non-numeric tree `SIZE`, `include` without `--trusted`, or a `--trusted` line that is not a key exited 1.
- `rfc9162-tiles`: Opening or refreshing a `PackStore` stops at a record head that declares more bytes than the file holds before sizing a buffer for it.
  A torn head after a crash cost an allocation of whatever length its bytes claimed, up to 4 GiB.
- `rfc9162-tiles`: `PosixStore::create_new` writes a temporary file and links it at the path, so a write cut short by an error or a crash leaves nothing there, as the store promises, instead of a partial file that every later `create_new` takes for one already stored.
  The root must be on a file system with hard links.
- `rfc9162-tiles`: `PosixStore` handles in one process draw temporary file names from one counter, so two handles on one root no longer write the same temporary file and rename each other's bytes into place.
  A temporary name that is already taken is passed over rather than truncated, and a temporary file whose write fails is removed.
- `rfc9162-tiles`: `Writer::checkpoint` signs only a tree that extends the checkpoint already published under its origin: the same root at that size, or a larger tree the tiles prove consistent with it.
  A tree of the published size with another root, or a larger one that does not extend it, is `Error::Corrupt`, where it was signed.

### Documentation

- The install and getting-started docs now state the minimum supported Rust version (1.85) before `cargo add`, and `docs/examples/Cargo.toml` now inherits the workspace `rust-version` so the examples package declares the same compiler floor as the crates.
- The sidecar reference and the log how-to describe `prove` and `verify-proof`, including a proof that still checks after a later snapshot.
- `rfc9162-log`: The `Recovery::quarantined` doc says what it counts: store paths of the data log beyond its tree state that opening the store moved to `.state/torn-<utc>`.
  It said entries.
- `rfc9162-log`: The `sidecar` module doc and `sidecar_keys` list every lookup key an entry gets: `path=`, `blob=` for a put, and `origin=` for a child's checkpoint.
  They left out `origin=`.
- `rfc9162-log`: The `store` module doc describes the run format the writer writes, v3: front-coded blocks of `BLOCK_PAIRS` pairs behind a block index.
  It said v2 and pointed at `RUN_MAGIC`, which only readers still accept.
- `rfc9162`: `Head.root`, `verify_inclusion` and `verify_consistency` say that a root is the lower-case hex `hex` writes: the same root in upper case does not verify, so a head has one form for `Head::material` to sign.
  They said only "hex".

### Miscellaneous

- Added `rfc9162-sidecar verify` for offline checkpoint verification against trusted signed-note key lines, with optional inclusion proof verification for a path at the signed checkpoint.
- Inclusion and consistency proofs at sizes 0, 1, 2 and either side of a power of two are checked against a second tree, and a flipped, truncated or extended proof is rejected.
- `scripts/build-docs.sh` and `docs/examples/sidecar-demo.sh` ask `cargo metadata` for the target directory, so the book's transcripts and API docs come from the builds cargo just made when `CARGO_TARGET_DIR` or a configured target-dir moves them out of `target/`.
  They read `target/` under the checkout, and ran stale binaries or none; the docs workflow now builds outside the checkout.


## 0.10.0 (2026-11-09)

### Features

- `rfc9162-log`: index runs are written in run format v2, which front-codes each key against the one before it and stores each log index as a varint offset from the run's first entry; a run of 100000 entries takes about half the bytes of v1. v1 runs stay readable.
- `rfc9162-log`: index runs are written in run format v3, sorted pairs in front-coded blocks of 64 behind a block index of first keys, so a lookup decodes only the blocks that can hold its key instead of the whole run. At 1000000 entries `Index::find` takes about 130 µs at p50 against about 1 ms for a scan of the store. v1 and v2 runs stay readable.
- `rfc9162-tiles`: `PackStore::open_shared` and `open_shared_waiting` open a writer that takes the pack lock for each change instead of for its lifetime, so several processes can write one pack. Under the lock the writer reads what others appended, reopens after another's compaction and truncates a torn tail before applying its change.
- `rfc9162-tiles`: a compaction writes the pack's live table as its first record, so opening a compacted pack reads that index and the records after it rather than every record. A pack in the v1 layout opens by scanning and takes the index at its next compaction.

### Fixes

- `rfc9162-tiles`: an index record whose digest or bounds do not hold is stepped over and the pack is scanned, rather than read as a torn tail; a rename read by the scan gives back the bytes `live_bytes` had counted for the path.

### Documentation

- The top README shows the sidecar workflow: init, sync, snapshot, history and diff from a shell, one signed file beside the tree, and nesting a stack's checkpoint under a site's.


## 0.9.0 (2026-11-08)

### Features

- `rfc9162-sidecar`, a binary in `rfc9162-log`: `init`, `sync`, `snapshot`, `history`, `tree`, `diff`, `blob` and `include` over a project directory from a shell, the sidecar at `DIR/.sidecar/pack`, the signing key a PKCS#8 PEM.


## 0.8.1 (2026-11-08)

### Fixes

- `rfc9162-tiles`: a reader at an older size reads a partial tile or bundle the writer has since widened from the widest partial or the full one, whose prefix it is. With a writer keeping only the widest partial, a reader at a signed checkpoint behind the tail failed with a missing tile.


## 0.8.0 (2026-11-08)

### Features

- `Sidecar::include_checkpoint` logs a child project's signed checkpoint under a path, verified against trusted keys and refused when it does not extend the child's last logged checkpoint, so a parent log's checkpoint signs its children's; `checkpoints(path)` reads them back.
- `Sidecar::sync_dir` records the regular files under a directory against the tree the log holds, the way etckeeper commits `/etc`: a file the log lacks or holds with other bytes is a put, a path the directory lacks is a delete, an unchanged file is left alone, and every change goes in one batch after its blob.
- `rfc9162-log::Sidecar`: a sidecar log beside a project tree. Every change to a path is a JSON entry keyed `path=` and `blob=`, its bytes a content-addressed blob stored once in the same store before the entry that names it; `history`, `under`, `tree_at`, `diff` read it back with proofs, and `snapshot` seals the tail and signs the log. Over a `PackStore` the whole history is one file and its lock.


## 0.7.0 (2026-11-08)

### Features

- New crate `rfc9162-tiles`: tiled, indexed storage for an `rfc9162` log in the C2SP tlog-tiles layout (256-hash tiles, 256-entry bundles, partial tiles for the tail), a locked writer that writes bundles, tiles, index sidecars, manifest and tree state in that order and quarantines a torn tail on open, a reader that checks every tile against the trusted root and assembles inclusion and consistency proofs identical to the flat crate's, per-bundle key sidecars with a split-block Bloom filter and a manifest for `find`, and C2SP checkpoints as Ed25519 signed notes with cosignature/v1 verification.
- `rfc9162-log` is published: an authenticated, indexed, append-only log over the other two crates. Keys are sorted into runs whose manifests are themselves entries, so the checkpoint signs the index and a lookup returns an inclusion path for the entry and for the run that located it; compaction writes a new run and logs it, the replaced runs stay provable; `Store::open_split` keeps a data tile log of the caller's entries alone and the runs and manifests in an index log beside it with its own checkpoint, so a consumer that signs its own head over the data log is unchanged.
- `rfc9162-tiles::PackStore`: a `TileStore` over one append-only file, so a log costs a constant number of inodes however long its history. Each record is a path with its bytes, a deletion or a rename and ends in a SHA-256, so a torn tail is found and ignored; bodies that shrink under DEFLATE are stored compressed; `compact` rewrites the pack with one record per live path. One writer holds `<pack>.lock`; readers open without a lock, see a writer's appends, and reopen after a compaction.

### Fixes

- `rfc9162-tiles`: a tail tile keeps only its widest partial. Every width a partial bundle or hash tile passed through stayed until the full tile existed, up to 255 files per level per tail tile; the tree state names the widest, which covers the narrower ones, so those are removed with each write.

### Miscellaneous

- The two crates live in their own repository, with the history of the commits that wrote them.
  `rfc9162-tiles` requires `rfc9162` at the one workspace version, and the publish workflow publishes `rfc9162` before `rfc9162-tiles`.


## 0.6.1 (2026-11-05)

### Features

- `rfc9162`: the Merkle tree of RFC 9162 (doi:10.17487/RFC9162) as pure functions over 32-byte leaf hashes.
  Leaf `SHA-256(0x00 || entry)`, node `SHA-256(0x01 || left || right)`, the root over a leaf slice, inclusion and consistency proofs, the checks for both, and a `Head` whose `material(domain)` is what a log signs.
  The crate stores nothing and serialises nothing.
  This release was published from the deedar repository, whose deed log builds on it; the version number is deedar's at the time.
