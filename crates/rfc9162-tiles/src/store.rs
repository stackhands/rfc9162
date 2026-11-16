//! Where tiles live: a trait over store paths, a POSIX directory behind it,
//! and an in-memory store for tests and single-process use.
//!
//! Paths are `/`-separated and relative to the store root. A write lands
//! whole or not at all: the POSIX store writes a temporary file under the
//! root's `.tmp`, syncs it, renames it over the path and syncs the
//! directory, as Tessera's POSIX storage does. `create_new` links the
//! temporary file at the path instead, which fails when something is
//! there, so the root must be on a file system with hard links.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Byte storage keyed by store path.
pub trait TileStore {
    /// The bytes at `path`, or nothing when there is no such file.
    fn get(&self, path: &str) -> io::Result<Option<Vec<u8>>>;
    /// Writes `bytes` at `path`, whole or not at all, replacing what is there.
    fn put(&self, path: &str, bytes: &[u8]) -> io::Result<()>;
    /// Writes `bytes` at `path`, whole or not at all, only when nothing is
    /// there; `false` when something is.
    fn create_new(&self, path: &str, bytes: &[u8]) -> io::Result<bool>;
    /// Removes `path`; `false` when there was nothing to remove.
    fn delete(&self, path: &str) -> io::Result<bool>;
    /// Moves `from` to `to`, replacing what is at `to`.
    fn rename(&self, from: &str, to: &str) -> io::Result<()>;
    /// Every file path under `prefix` (a directory path without a trailing
    /// slash, or the empty string for the whole store), sorted.
    fn list(&self, prefix: &str) -> io::Result<Vec<String>>;
    /// Whether anything is stored at `path`.
    fn exists(&self, path: &str) -> io::Result<bool> {
        Ok(self.get(path)?.is_some())
    }
}

impl<T: TileStore + ?Sized> TileStore for &T {
    fn get(&self, path: &str) -> io::Result<Option<Vec<u8>>> {
        (**self).get(path)
    }
    fn put(&self, path: &str, bytes: &[u8]) -> io::Result<()> {
        (**self).put(path, bytes)
    }
    fn create_new(&self, path: &str, bytes: &[u8]) -> io::Result<bool> {
        (**self).create_new(path, bytes)
    }
    fn delete(&self, path: &str) -> io::Result<bool> {
        (**self).delete(path)
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        (**self).rename(from, to)
    }
    fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        (**self).list(prefix)
    }
    fn exists(&self, path: &str) -> io::Result<bool> {
        (**self).exists(path)
    }
}

impl<T: TileStore + ?Sized> TileStore for Arc<T> {
    fn get(&self, path: &str) -> io::Result<Option<Vec<u8>>> {
        (**self).get(path)
    }
    fn put(&self, path: &str, bytes: &[u8]) -> io::Result<()> {
        (**self).put(path, bytes)
    }
    fn create_new(&self, path: &str, bytes: &[u8]) -> io::Result<bool> {
        (**self).create_new(path, bytes)
    }
    fn delete(&self, path: &str) -> io::Result<bool> {
        (**self).delete(path)
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        (**self).rename(from, to)
    }
    fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        (**self).list(prefix)
    }
    fn exists(&self, path: &str) -> io::Result<bool> {
        (**self).exists(path)
    }
}

/// Numbers for temporary file names, drawn by every `PosixStore` in the
/// process, so that two handles on one root never pick the same name.
static TEMP_NUMBER: AtomicU64 = AtomicU64::new(0);

/// A directory. Every path is resolved under the root; `..`, absolute paths
/// and empty elements are refused.
#[derive(Debug, Clone)]
pub struct PosixStore {
    root: PathBuf,
}

impl PosixStore {
    /// A store rooted at `root`, created when absent.
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        fs::create_dir_all(root.join(".tmp"))?;
        Ok(Self { root })
    }

    /// The directory the store lives in.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn resolve(&self, path: &str) -> io::Result<PathBuf> {
        if path.is_empty() {
            return Ok(self.root.clone());
        }
        let relative = Path::new(path);
        if relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("store path {path:?} leaves the store"),
            ));
        }
        Ok(self.root.join(relative))
    }

    /// A new file under `.tmp` holding `bytes`, synced. It is named after the
    /// process id and a number from `TEMP_NUMBER`; a name that is taken, as
    /// by an earlier process with the same id, is passed over rather than
    /// truncated. A write that fails removes the file.
    fn write_temp(&self, bytes: &[u8]) -> io::Result<PathBuf> {
        loop {
            let n = TEMP_NUMBER.fetch_add(1, Ordering::Relaxed);
            let name = format!("{}-{n}", std::process::id());
            let temp = self.root.join(".tmp").join(name);
            let mut file = match OpenOptions::new().write(true).create_new(true).open(&temp) {
                Ok(file) => file,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            };
            if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
                drop(file);
                let _ = fs::remove_file(&temp);
                return Err(e);
            }
            return Ok(temp);
        }
    }

    fn sync_dir(dir: &Path) -> io::Result<()> {
        File::open(dir)?.sync_all()
    }

    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                Self::walk(&path, root, out)?;
            } else {
                let relative = path.strip_prefix(root).map_err(io::Error::other)?;
                let text = relative
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push(text);
            }
        }
        Ok(())
    }
}

impl TileStore for PosixStore {
    fn get(&self, path: &str) -> io::Result<Option<Vec<u8>>> {
        match fs::read(self.resolve(path)?) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn put(&self, path: &str, bytes: &[u8]) -> io::Result<()> {
        let target = self.resolve(path)?;
        let parent = target
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent"))?;
        fs::create_dir_all(parent)?;
        let temp = self.write_temp(bytes)?;
        fs::rename(&temp, &target)?;
        Self::sync_dir(parent)
    }

    fn create_new(&self, path: &str, bytes: &[u8]) -> io::Result<bool> {
        let target = self.resolve(path)?;
        let parent = target
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent"))?;
        fs::create_dir_all(parent)?;
        let temp = self.write_temp(bytes)?;
        let linked = fs::hard_link(&temp, &target);
        // The bytes are at the path or nowhere; the temporary name goes
        // either way, and failing to remove it leaves only a stray file.
        let _ = fs::remove_file(&temp);
        match linked {
            Ok(()) => {
                Self::sync_dir(parent)?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn delete(&self, path: &str) -> io::Result<bool> {
        let target = self.resolve(path)?;
        match fs::remove_file(&target) {
            Ok(()) => {
                if let Some(parent) = target.parent() {
                    Self::sync_dir(parent)?;
                }
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let source = self.resolve(from)?;
        let target = self.resolve(to)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&source, &target)?;
        if let Some(parent) = target.parent() {
            Self::sync_dir(parent)?;
        }
        if let Some(parent) = source.parent() {
            Self::sync_dir(parent)?;
        }
        Ok(())
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        let dir = self.resolve(prefix)?;
        let mut out = Vec::new();
        match fs::metadata(&dir) {
            Ok(meta) if meta.is_dir() => Self::walk(&dir, &self.root, &mut out)?,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if prefix.is_empty() {
            out.retain(|p| !p.starts_with(".tmp/"));
        }
        out.sort();
        Ok(out)
    }

    fn exists(&self, path: &str) -> io::Result<bool> {
        Ok(self.resolve(path)?.is_file())
    }
}

/// Files in memory. Clones share the same files, so a writer and a reader can
/// hold one store.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes stored, over every file.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.files.lock().unwrap().values().map(Vec::len).sum()
    }

    /// Bytes stored under `prefix`.
    #[must_use]
    pub fn bytes_under(&self, prefix: &str) -> usize {
        self.files
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| under(k, prefix))
            .map(|(_, v)| v.len())
            .sum()
    }
}

fn under(path: &str, prefix: &str) -> bool {
    prefix.is_empty()
        || path
            .strip_prefix(prefix)
            .is_some_and(|r| r.starts_with('/'))
}

impl TileStore for MemoryStore {
    fn get(&self, path: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(self.files.lock().unwrap().get(path).cloned())
    }

    fn put(&self, path: &str, bytes: &[u8]) -> io::Result<()> {
        self.files
            .lock()
            .unwrap()
            .insert(path.to_string(), bytes.to_vec());
        Ok(())
    }

    fn create_new(&self, path: &str, bytes: &[u8]) -> io::Result<bool> {
        let mut files = self.files.lock().unwrap();
        if files.contains_key(path) {
            return Ok(false);
        }
        files.insert(path.to_string(), bytes.to_vec());
        Ok(true)
    }

    fn delete(&self, path: &str) -> io::Result<bool> {
        Ok(self.files.lock().unwrap().remove(path).is_some())
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let mut files = self.files.lock().unwrap();
        let bytes = files
            .remove(from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, from.to_string()))?;
        files.insert(to.to_string(), bytes);
        Ok(())
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        Ok(self
            .files
            .lock()
            .unwrap()
            .keys()
            .filter(|k| under(k, prefix))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_handles_on_one_root_never_share_a_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let a = PosixStore::open(dir.path()).unwrap();
        let b = PosixStore::open(dir.path()).unwrap();
        let from_a = a.write_temp(b"from a").unwrap();
        let from_b = b.write_temp(b"from b").unwrap();
        assert_ne!(from_a, from_b);
        assert_eq!(fs::read(&from_a).unwrap(), b"from a");
        assert_eq!(fs::read(&from_b).unwrap(), b"from b");
    }

    #[test]
    fn a_temporary_name_already_taken_is_passed_over() {
        let dir = tempfile::tempdir().unwrap();
        let store = PosixStore::open(dir.path()).unwrap();
        let next = TEMP_NUMBER.load(Ordering::Relaxed);
        let taken: Vec<PathBuf> = (next..next + 3)
            .map(|n| {
                dir.path()
                    .join(".tmp")
                    .join(format!("{}-{n}", std::process::id()))
            })
            .collect();
        for path in &taken {
            fs::write(path, b"left behind").unwrap();
        }
        let temp = store.write_temp(b"new").unwrap();
        assert!(!taken.contains(&temp));
        assert_eq!(fs::read(&temp).unwrap(), b"new");
        for path in &taken {
            assert_eq!(fs::read(path).unwrap(), b"left behind");
        }
    }
}
