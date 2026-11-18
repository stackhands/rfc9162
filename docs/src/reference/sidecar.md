# rfc9162-sidecar

The binary in the `rfc9162-log` crate. Its rustdoc page is [`rfc9162_sidecar`](../api/rfc9162_sidecar/index.html). The pack for `--dir DIR` is `DIR/.sidecar/pack`. Each command that names a directory opens that pack, holds the writer lock while it runs, and prints one line per result. `verify-proof` reads a proof file and does not open a pack. Exit status 0 means the command finished. Exit status 2 means the command line is rejected; it is checked before the pack is opened, so nothing is created. Exit status 1 means the store or a proof failed.

```text
rfc9162-sidecar init     --dir DIR
rfc9162-sidecar sync     --dir DIR [--skip NAME]... [--meta K=V]...
rfc9162-sidecar snapshot --dir DIR --key KEY.pem --origin ORIGIN
rfc9162-sidecar history  --dir DIR PATH
rfc9162-sidecar tree     --dir DIR [SIZE]
rfc9162-sidecar diff     --dir DIR FROM TO
rfc9162-sidecar blob     --dir DIR HEX [--out FILE]
rfc9162-sidecar include  --dir DIR PATH --note FILE --trusted KEYLINE... [--meta K=V]...
rfc9162-sidecar verify   --dir DIR --trusted KEYLINE... [--path REL_PATH]
rfc9162-sidecar prove    --dir DIR --path PATH [--index N]
rfc9162-sidecar verify-proof --proof FILE --trusted KEYLINE... [--blob-file FILE]
```

`--meta` repeats. The value is `K=V` and is stored on the change. `--skip` repeats and names a top-level directory entry that `sync` leaves alone. The binary always skips `.sidecar`. `--key` is a PKCS#8 PEM Ed25519 key (`-----BEGIN PRIVATE KEY-----`). `--trusted` repeats and is a verifier line, `name+keyid+base64`. `--note` is the signed checkpoint text of a child log.

| Command | Output |
| --- | --- |
| `init` | `sidecar at DIR/.sidecar size SIZE` |
| `sync` | one `added`, `changed` or `deleted` line per path, then `synced: N added, N changed, N deleted, N unchanged; entries START..END; size SIZE` |
| `snapshot` | `snapshot ORIGIN size SIZE root HEX` |
| `history` | one tab-separated line per change of `PATH`, oldest first |
| `tree` | one tab-separated line per live path at `SIZE`, or at the current size when `SIZE` is omitted |
| `diff` | changes with index in `FROM..TO`, `TO` clamped to the current size |
| `blob` | the bytes of blob `HEX` on stdout, or written to `--out` |
| `include` | `included PATH at INDEX` |
| `verify` | `verified checkpoint ORIGIN size SIZE root HEX by N trusted key(s)` and, with `--path`, `verified inclusion PATH index INDEX op OP steps N` |
| `prove` | one JSON object: the checkpoint note, the entry bytes, the inclusion path, and the blob hash of a put |
| `verify-proof` | `verified proof PATH index INDEX size SIZE root HEX by N trusted key(s)` |

A history, tree or diff line for a put is:

```text
INDEX  put  PATH  BLOBHEX  SIZE
```

A delete omits the blob and the size. A checkpoint line carries the child's origin. The fields are separated by tabs. The [log how-to](../howto/rfc9162-log.md) includes a transcript of each command.

`snapshot` seals the unsealed tail when there is one, then signs the log. `include` verifies the note against the trusted keys. A child note with a smaller size, or the same size and another root, is refused.
`verify` checks the signed checkpoint in `DIR/.sidecar/pack/checkpoint` against `--trusted` keys, then opens the log at that checkpoint size and root. With `--path`, it verifies the latest entry for that path at the checkpoint with the reader's inclusion path.

`prove` reads that same checkpoint and writes a JSON object for one path. `--index` selects an entry; without it, the object is the latest entry for the path whose index is below the checkpoint size. The object carries the checkpoint note, the exact entry bytes, the inclusion path as lowercase hex, and, for a put, the blob hash. A later `snapshot` replaces `pack/checkpoint`. The object still verifies, because it holds the note it was proved against.

`verify-proof` checks that object. It does not read a log. `--trusted` is the verifier line of a key that signed the note, repeated when several keys are trusted. `--blob-file` checks that the file's SHA-256 is the object's blob hash. A note no trusted key signed, an inclusion path that does not meet the checkpoint root, or a blob that differs is exit status 1.
