//! The RFC 9162 tree, written out beside the crate and checked against it.
//!
//! Leaf and node hashes are the crate's. The split, the root and both proofs
//! are this file's, so a mistake in the crate's recursion does not hide in a
//! test that calls the same function twice. Sizes cover the empty tree, one
//! leaf, two leaves, and the two shapes on either side of a power of two.

use rfc9162::{
    consistency_proof, hex, inclusion_proof, leaf_hash, node_hash, root, verify_consistency,
    verify_inclusion,
};

fn split(width: usize) -> usize {
    let mut k = 1usize;
    while k * 2 < width {
        k *= 2;
    }
    k
}

fn empty_root() -> [u8; 32] {
    let text = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).unwrap();
        *slot = u8::from_str_radix(pair, 16).unwrap();
    }
    out
}

fn naive_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&naive_root(&leaves[..k]), &naive_root(&leaves[k..]))
        }
    }
}

fn naive_inclusion(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n == 1 {
        return Vec::new();
    }
    let k = split(n);
    if index < k {
        let mut path = naive_inclusion(&leaves[..k], index);
        path.push(naive_root(&leaves[k..]));
        path
    } else {
        let mut path = naive_inclusion(&leaves[k..], index - k);
        path.push(naive_root(&leaves[..k]));
        path
    }
}

fn naive_consistency(leaves: &[[u8; 32]], old: usize, known: bool) -> Vec<[u8; 32]> {
    if old == leaves.len() {
        return if known {
            Vec::new()
        } else {
            vec![naive_root(leaves)]
        };
    }
    let k = split(leaves.len());
    if old <= k {
        let mut path = naive_consistency(&leaves[..k], old, known);
        path.push(naive_root(&leaves[k..]));
        path
    } else {
        let mut path = naive_consistency(&leaves[k..], old - k, false);
        path.push(naive_root(&leaves[..k]));
        path
    }
}

fn leaves(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| leaf_hash(format!("edge-{i}").as_bytes()))
        .collect()
}

#[test]
fn edge_sizes_match_a_naive_tree() {
    for size in [0usize, 1, 2, 3, 4, 5, 8, 9, 16, 17] {
        let set = leaves(size);
        assert_eq!(root(&set), naive_root(&set), "root of {size}");
        if size == 0 {
            assert!(inclusion_proof(&set, 0).is_none());
            assert!(consistency_proof(&set, 0).is_none());
            assert!(!verify_inclusion(
                &leaf_hash(b"x"),
                0,
                0,
                &[],
                &hex(&root(&[]))
            ));
            continue;
        }
        let head = hex(&root(&set));
        for index in 0..size {
            let path = inclusion_proof(&set, index).unwrap();
            assert_eq!(
                path,
                naive_inclusion(&set, index),
                "inclusion {size}/{index}"
            );
            assert!(verify_inclusion(&set[index], index, size, &path, &head));
            if !path.is_empty() {
                let mut flipped = path.clone();
                flipped[0][0] ^= 0xff;
                assert!(!verify_inclusion(&set[index], index, size, &flipped, &head));
                assert!(!verify_inclusion(
                    &set[index],
                    index,
                    size,
                    &path[..path.len() - 1],
                    &head
                ));
            }
            let mut extra = path.clone();
            extra.push([9u8; 32]);
            assert!(!verify_inclusion(&set[index], index, size, &extra, &head));
            if size > 1 {
                let other = (index + 1) % size;
                assert!(!verify_inclusion(&set[index], other, size, &path, &head));
            }
        }
        for old in 1..=size {
            let proof = consistency_proof(&set, old).unwrap();
            assert_eq!(
                proof,
                naive_consistency(&set, old, true),
                "consistency {old} of {size}"
            );
            let earlier = hex(&root(&set[..old]));
            assert!(verify_consistency(old, &earlier, size, &head, &proof));
            if old != size && !proof.is_empty() {
                let mut flipped = proof.clone();
                flipped[0][0] ^= 0xff;
                assert!(!verify_consistency(old, &earlier, size, &head, &flipped));
                assert!(!verify_consistency(old, &earlier, size, &head, &[]));
            }
        }
        assert!(consistency_proof(&set, 0).is_none());
        assert!(consistency_proof(&set, size + 1).is_none());
        assert!(!verify_consistency(0, &hex(&root(&[])), size, &head, &[]));
    }
}
