`scripts/build-docs.sh` and `docs/examples/sidecar-demo.sh` ask `cargo metadata` for the target directory, so the book's transcripts and API docs come from the builds cargo just made when `CARGO_TARGET_DIR` or a configured target-dir moves them out of `target/`.
They read `target/` under the checkout, and ran stale binaries or none; the docs workflow now builds outside the checkout.
