//! A torn record head costs the scan that opens a pack no more memory than
//! the bytes that are there. The test counts every allocation in this
//! binary, so it is the only test here.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

use rfc9162_tiles::{PackStore, TileStore};

/// The system allocator, counting the bytes held and the most held at once.
struct Counting;

static HELD: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let held = HELD.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(held, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        HELD.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

#[test]
fn a_torn_head_declaring_a_large_record_is_not_allocated() {
    let dir = tempfile::tempdir().unwrap();
    let pack = dir.path().join("pack");
    PackStore::open(&pack)
        .unwrap()
        .put("kept", b"kept bytes")
        .unwrap();
    // A crash after a put's head: kind, codec, a 4-byte path and 256 MiB
    // stored and raw, with none of them written.
    let declared = 256u32 << 20;
    let mut head = vec![1, 0, 0, 4];
    head.extend_from_slice(&declared.to_be_bytes());
    head.extend_from_slice(&declared.to_be_bytes());
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&pack)
        .unwrap();
    file.write_all(&head).unwrap();
    drop(file);

    let before = HELD.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let reader = PackStore::open_read(&pack).unwrap();
    let peak = PEAK.load(Ordering::Relaxed) - before;
    assert_eq!(
        reader.get("kept").unwrap().as_deref(),
        Some(&b"kept bytes"[..])
    );
    assert!(peak < 1 << 20, "opening the pack held {peak} bytes at once");
}
