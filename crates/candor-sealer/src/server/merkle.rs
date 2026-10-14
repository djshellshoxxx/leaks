// SPDX-License-Identifier: AGPL-3.0-or-later
//! RFC 6962 / RFC 9162 Merkle tree hashing for the Key Directory log (04 §14.2:
//! leaf hash `H(0x00 ‖ leaf)`, interior node `H(0x01 ‖ left ‖ right)`, SHA-256
//! from `candor-core`).
//!
//! **Migration note (AUD-RM2-SEA-19):** `candor-core` has no Merkle primitives
//! yet. This module is self-contained (only `candor_core::hash::sha256` and
//! `candor_core::kdf::ct_eq`) so that it can move into `candor-core` unchanged;
//! the RFC 6962 test vectors below move with it.
//!
//! Verification functions ([`root_of`], [`verify_inclusion`],
//! [`verify_consistency`]) are iterative and bounded; nothing recurses on the
//! number of leaves. The proof generators ([`inclusion_proof`],
//! [`consistency_proof`], [`root`]) are tooling and test helpers: they recurse
//! to depth `log2(n)` only.

use candor_core::hash::sha256;
use candor_core::kdf::ct_eq;

/// Longest proof accepted (a `u64`-sized tree has at most 64 levels).
pub const MAX_PROOF_LEN: usize = 64;

/// `HASH(0x00 ‖ leaf)`.
#[must_use]
pub fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    sha256(&[&[0x00], leaf])
}

/// `HASH(0x01 ‖ left ‖ right)`.
#[must_use]
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&[&[0x01], left, right])
}

/// `MTH(D[n])` over leaf hashes (RFC 9162 §2.1.1), computed iteratively with a
/// stack of perfect subtrees (at most 64 entries): merge equal-sized subtrees
/// left to right, then fold the remaining ones right to left. The empty tree
/// hashes to `SHA-256("")`.
#[must_use]
pub fn root_of<I>(leaf_hashes: I) -> [u8; 32]
where
    I: IntoIterator<Item = [u8; 32]>,
{
    // (hash, number of leaves in the perfect subtree)
    let mut stack: Vec<([u8; 32], u64)> = Vec::with_capacity(65);
    for h in leaf_hashes {
        let mut cur = (h, 1u64);
        while let Some(&(top, size)) = stack.last() {
            if size != cur.1 {
                break;
            }
            stack.pop();
            cur = (node_hash(&top, &cur.0), size.saturating_mul(2));
        }
        stack.push(cur);
    }
    let Some((mut acc, _)) = stack.pop() else {
        return sha256(&[]);
    };
    while let Some((left, _)) = stack.pop() {
        acc = node_hash(&left, &acc);
    }
    acc
}

/// Recursive `MTH` (tooling and tests; depth `log2(n)`).
#[must_use]
pub fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
    root_of(leaves.iter().copied())
}

fn split(n: usize) -> usize {
    // Largest power of two strictly below n (n ≥ 2).
    let mut k = 1usize;
    while k.checked_mul(2).is_some_and(|d| d < n) {
        k = k.saturating_mul(2);
    }
    k
}

fn path(m: usize, leaves: &[[u8; 32]], out: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if n < 2 {
        return;
    }
    let k = split(n);
    let (l, r) = leaves.split_at(k);
    if m < k {
        path(m, l, out);
        out.push(root(r));
    } else {
        path(m.saturating_sub(k), r, out);
        out.push(root(l));
    }
}

/// `PATH(m, D[n])` (RFC 9162 §2.1.3.1). Tooling and tests only.
#[must_use]
pub fn inclusion_proof(index: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    if index < leaves.len() {
        path(index, leaves, &mut out);
    }
    out
}

/// Verify an inclusion proof (RFC 9162 §2.1.3.2): `leaf` (a leaf *hash*) is at
/// `index` in the tree of `tree_size` leaves with root `root_hash`.
#[must_use]
pub fn verify_inclusion(
    index: u64,
    tree_size: u64,
    leaf: &[u8; 32],
    proof: &[[u8; 32]],
    root_hash: &[u8; 32],
) -> bool {
    if index >= tree_size || proof.len() > MAX_PROOF_LEN {
        return false;
    }
    let mut fn_ = index;
    let Some(mut sn) = tree_size.checked_sub(1) else {
        return false;
    };
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && ct_eq(&r, root_hash)
}

fn subproof(m: usize, leaves: &[[u8; 32]], complete: bool, out: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if m == n {
        if !complete {
            out.push(root(leaves));
        }
        return;
    }
    if n < 2 {
        return;
    }
    let k = split(n);
    let (l, r) = leaves.split_at(k);
    if m <= k {
        subproof(m, l, complete, out);
        out.push(root(r));
    } else {
        subproof(m.saturating_sub(k), r, false, out);
        out.push(root(l));
    }
}

/// `PROOF(m, D[n])` (RFC 9162 §2.1.4.1). Tooling and tests only.
#[must_use]
pub fn consistency_proof(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    if m == 0 || m > leaves.len() {
        return out;
    }
    subproof(m, leaves, true, &mut out);
    out
}

/// Verify a consistency proof (RFC 9162 §2.1.4.2). Iterative and bounded.
#[must_use]
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_hash: &[u8; 32],
    second_hash: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if proof.len() > MAX_PROOF_LEN || first == 0 || first > second {
        return false;
    }
    if first == second {
        return proof.is_empty() && ct_eq(first_hash, second_hash);
    }
    let mut nodes: Vec<[u8; 32]> = Vec::with_capacity(proof.len().saturating_add(1));
    if first.is_power_of_two() {
        nodes.push(*first_hash);
    }
    nodes.extend_from_slice(proof);
    let Some((start, rest)) = nodes.split_first() else {
        return false;
    };
    let (Some(mut fn_), Some(mut sn)) = (first.checked_sub(1), second.checked_sub(1)) else {
        return false;
    };
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let mut fr = *start;
    let mut sr = *start;
    for c in rest {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && ct_eq(&fr, first_hash) && ct_eq(&sr, second_hash)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    fn unhex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// The 8 leaf inputs of the RFC 6962 reference test vectors
    /// (certificate-transparency `merkle_tree_test`).
    fn rfc6962_leaves() -> Vec<[u8; 32]> {
        let inputs: [&[u8]; 8] = [
            b"",
            b"\x00",
            b"\x10",
            b"\x20\x21",
            b"\x30\x31",
            b"\x40\x41\x42\x43",
            b"\x50\x51\x52\x53\x54\x55\x56\x57",
            b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
        ];
        inputs.iter().map(|i| leaf_hash(i)).collect()
    }

    /// Known-answer roots for the first 1..=8 leaves, the empty tree, and
    /// inclusion paths, from the RFC 6962 reference vectors.
    #[test]
    fn rfc6962_known_answers() {
        assert_eq!(
            root_of(core::iter::empty()),
            unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        let roots = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        let l = rfc6962_leaves();
        for (n, want) in roots.iter().enumerate() {
            assert_eq!(root(&l[..=n]), unhex(want), "root of {}", n + 1);
        }
        let paths: [(usize, usize, &[&str]); 4] = [
            (
                0,
                8,
                &[
                    "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                    "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
                ],
            ),
            (
                5,
                8,
                &[
                    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                    "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
                ],
            ),
            (
                2,
                3,
                &["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"],
            ),
            (
                1,
                5,
                &[
                    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                ],
            ),
        ];
        for (i, n, want) in paths {
            let want: Vec<[u8; 32]> = want.iter().map(|h| unhex(h)).collect();
            assert_eq!(inclusion_proof(i, &l[..n]), want, "path {i} of {n}");
            let r = root(&l[..n]);
            assert!(verify_inclusion(i as u64, n as u64, &l[i], &want, &r));
        }
    }

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| leaf_hash(&i.to_be_bytes())).collect()
    }

    /// The iterative root equals the recursive RFC definition for all n ≤ 70.
    #[test]
    fn iterative_root_matches_definition() {
        fn mth(l: &[[u8; 32]]) -> [u8; 32] {
            match l {
                [] => sha256(&[]),
                [one] => *one,
                _ => {
                    let k = split(l.len());
                    node_hash(&mth(&l[..k]), &mth(&l[k..]))
                }
            }
        }
        let all = leaves(70);
        for n in 0..=70 {
            assert_eq!(root(&all[..n]), mth(&all[..n]), "{n}");
        }
    }

    /// Every inclusion proof up to n = 40 verifies; wrong index, size, leaf,
    /// root, a flipped node, a truncated or extended proof all fail.
    #[test]
    fn inclusion_proofs_round_trip_and_reject_tampering() {
        let all = leaves(40);
        for n in 1..=40usize {
            let r = root(&all[..n]);
            for i in 0..n {
                let p = inclusion_proof(i, &all[..n]);
                let (i64_, n64) = (i as u64, n as u64);
                assert!(verify_inclusion(i64_, n64, &all[i], &p, &r), "{i} {n}");
                assert!(!verify_inclusion(n64, n64, &all[i], &p, &r));
                assert!(!verify_inclusion(i64_, n64, &[0xaa; 32], &p, &r));
                assert!(!verify_inclusion(i64_, n64, &all[i], &p, &[0xbb; 32]));
                if n > 1 {
                    let other = if i == 0 { 1 } else { i - 1 };
                    assert!(!verify_inclusion(other as u64, n64, &all[i], &p, &r));
                }
                for k in 0..p.len() {
                    let mut bad = p.clone();
                    bad[k][0] ^= 1;
                    assert!(!verify_inclusion(i64_, n64, &all[i], &bad, &r));
                }
                let mut longer = p.clone();
                longer.push([0; 32]);
                assert!(!verify_inclusion(i64_, n64, &all[i], &longer, &r));
                if !p.is_empty() {
                    assert!(!verify_inclusion(i64_, n64, &all[i], &p[..p.len() - 1], &r));
                }
            }
        }
        assert!(!verify_inclusion(0, 0, &[0; 32], &[], &[0; 32]));
    }

    /// RFC 9162 consistency proofs: every (m, n) up to 40 verifies; any tamper,
    /// wrong size or wrong root fails.
    #[test]
    fn consistency_proofs_round_trip_and_reject_tampering() {
        let all = leaves(40);
        for n in 1..=40usize {
            let rn = root(&all[..n]);
            for m in 1..=n {
                let rm = root(&all[..m]);
                let p = consistency_proof(m, &all[..n]);
                let (m64, n64) = (m as u64, n as u64);
                assert!(verify_consistency(m64, n64, &rm, &rn, &p), "{m} {n}");
                if m < n {
                    assert!(!verify_consistency(m64, n64, &rn, &rn, &p));
                    assert!(!verify_consistency(m64, n64, &rm, &rm, &p));
                    for i in 0..p.len() {
                        let mut bad = p.clone();
                        bad[i][0] ^= 1;
                        assert!(!verify_consistency(m64, n64, &rm, &rn, &bad));
                    }
                    let mut longer = p.clone();
                    longer.push([0; 32]);
                    assert!(!verify_consistency(m64, n64, &rm, &rn, &longer));
                }
            }
        }
        assert!(!verify_consistency(0, 1, &[0; 32], &[0; 32], &[]));
        assert!(!verify_consistency(3, 2, &[0; 32], &[0; 32], &[]));
    }
}
