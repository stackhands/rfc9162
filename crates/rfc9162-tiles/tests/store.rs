//! PosixStore writes land whole or not at all.

use std::ffi::OsStr;
use std::process::{Command, Output};

use rfc9162_tiles::{PosixStore, TileStore};

/// Set in a child run of this binary to the store root it writes under.
const CHILD_ROOT: &str = "RFC9162_TILES_STORE_TEST_ROOT";

/// Runs the test `name` of this binary again with `root` in `CHILD_ROOT`,
/// under a file size limit of at most 8 KiB (`ulimit -f 8` counts 512-byte
/// blocks in dash and 1 KiB ones in bash) and with SIGXFSZ ignored, so a
/// write past the limit fails with EFBIG instead of killing the process.
fn run_under_file_size_limit(name: &str, root: &OsStr) -> Output {
    Command::new("sh")
        .arg("-c")
        .arg(r#"ulimit -f 8 && trap '' XFSZ && exec "$0" --exact "$1" --test-threads=1"#)
        .arg(std::env::current_exe().unwrap())
        .arg(name)
        .env(CHILD_ROOT, root)
        .output()
        .unwrap()
}

#[test]
fn a_create_new_cut_short_leaves_nothing_at_the_path() {
    let bytes = vec![7u8; 64 * 1024];
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let store = PosixStore::open(root).unwrap();
        assert!(store.create_new("tile/0/000", &bytes).is_err());
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let child = run_under_file_size_limit(
        "a_create_new_cut_short_leaves_nothing_at_the_path",
        dir.path().as_os_str(),
    );
    assert!(
        child.status.success(),
        "the child failed: {}{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let store = PosixStore::open(dir.path()).unwrap();
    assert_eq!(store.get("tile/0/000").unwrap().map(|b| b.len()), None);
    assert_eq!(
        std::fs::read_dir(dir.path().join(".tmp")).unwrap().count(),
        0
    );
    assert!(store.create_new("tile/0/000", &bytes).unwrap());
    assert_eq!(store.get("tile/0/000").unwrap(), Some(bytes));
}
