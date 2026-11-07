//! The wordlist cracking engine.
//!
//! Each target hash is compared against the digest of every candidate word.
//! The search is parallelized across threads with rayon.
//!
//! Candidates are handled as raw bytes (`&[u8]`) rather than `String`s: real
//! wordlists like rockyou.txt contain non-UTF-8 sequences, and passwords are
//! fundamentally byte strings. The wordlist buffer is split in place, so no
//! per-line allocation happens during the sweep.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;

use crate::hash::Algorithm;

#[derive(Clone, PartialEq, Eq)] //mbe side effects? Prob none
pub struct Target {
    pub digest: String,
    pub salt: Option<Vec<u8>>,
}

/// A single recovered password.
#[derive(Clone, Debug)]
pub struct Cracked {
    pub digest: String,
    pub plaintext: String,
}

/// Outcome of a cracking run.
pub struct Report {
    pub cracked: Vec<Cracked>,
    pub uncracked: Vec<Target>,
    pub words_tried: usize,
}

/// Strip a single trailing `\r` so Windows (CRLF) wordlists behave like Unix.
fn trim_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((b'\r', rest)) => rest,
        _ => line,
    }
}

/// Try to crack every hash in `targets` using the candidates in `buffer`.
///
/// `targets` must already be lowercase hex. `buffer` is the entire wordlist
/// file contents; it is split on `\n` in parallel and each line hashed once
/// with `algo`, then checked against all still-unsolved targets. Hashing a
/// candidate once per sweep keeps the expensive work to a single pass no
/// matter how many targets are supplied.
pub fn crack(algo: Algorithm, targets: &[Target], buffer: &[u8]) -> Report {
    // Normalize + dedupe targets for O(1) membership tests.
    // let target_set: HashSet<String> = targets.iter().cloned().collect();
    let unsalted: HashSet<String> = targets
        .iter()
        .filter(|t| t.salt.is_none())
        .map(|t| t.digest.clone())
        .collect();
    let salted: Vec<&Target> = targets.iter().filter(|t| t.salt.is_some()).collect();

    let counter = AtomicUsize::new(0);

    // Parallel split over the raw buffer: each line -> optional match.
    let hits: Vec<Cracked> = buffer
        .par_split(|&b| b == b'\n')
        .filter_map(|raw| {
            let word = trim_cr(raw);
            if word.is_empty() {
                return None;
            }
            counter.fetch_add(1, Ordering::Relaxed);

            // Handle bcrypt separately: it uses verification instead of hash comparison
            if algo == Algorithm::Bcrypt {
                for target in &unsalted {
                    if Algorithm::verify_bcrypt(target, word) {
                        return Some(Cracked {
                            digest: target.clone(),
                            plaintext: String::from_utf8_lossy(word).into_owned(),
                        });
                    }
                }
                return None;
            }

            let digest = algo.hash_hex(word);

            // Fast path: unsalted hashes
            if unsalted.contains(&digest) {
                return Some(Cracked {
                    digest,
                    plaintext: String::from_utf8_lossy(word).into_owned(),
                });
            }

            // Slower path: salted hashes
            for target in &salted {
                let salt = target.salt.as_ref().unwrap();

                let mut salted_input = Vec::with_capacity(salt.len() + word.len());

                // Currently assuming salt + password
                salted_input.extend_from_slice(salt);
                salted_input.extend_from_slice(word);

                let salted_digest = algo.hash_hex(&salted_input);

                if salted_digest == target.digest {
                    return Some(Cracked {
                        digest: salted_digest,
                        plaintext: String::from_utf8_lossy(word).into_owned(),
                    });
                }
            }

            None
        })
        .collect();

    // Keep the first match per target hash.
    let mut seen: HashSet<String> = HashSet::new();
    let mut cracked: Vec<Cracked> = Vec::new();
    for hit in hits {
        if seen.insert(hit.digest.clone()) {
            cracked.push(hit);
        }
    }

    let solved: HashSet<&String> = cracked.iter().map(|c| &c.digest).collect();
    let uncracked: Vec<Target> = targets
        .iter()
        .filter(|t| !solved.contains(&t.digest))
        .cloned()
        .collect();

    Report {
        cracked,
        uncracked,
        words_tried: counter.load(Ordering::Relaxed),
    }
}
