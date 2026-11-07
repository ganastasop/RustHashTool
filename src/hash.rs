//! Hash algorithm abstraction: computing digests and guessing an algorithm
//! from a hex digest's length.

use std::fmt;
use std::str::FromStr;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

/// Supported hash algorithms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Bcrypt,
}

impl Algorithm {
    /// Compute the hex-encoded digest of `input` for this algorithm.
    ///
    /// For bcrypt, returns the plaintext bcrypt hash (not hex-encoded).
    /// The output is always lowercase hex (except bcrypt), matching how the target hashes are
    /// normalized before comparison.
    pub fn hash_hex(self, input: &[u8]) -> String {
        match self {
            Algorithm::Md5 => hex::encode(Md5::digest(input)),
            Algorithm::Sha1 => hex::encode(Sha1::digest(input)),
            Algorithm::Sha256 => hex::encode(Sha256::digest(input)),
            Algorithm::Sha512 => hex::encode(Sha512::digest(input)),
            Algorithm::Bcrypt => {
                // Use bcrypt with a default cost of 12 (standard production value)
                // Note: for actual password verification, you'd compare against
                // an existing hash. Here we generate a new hash for comparison.
                bcrypt::hash(input, 12).unwrap_or_default()
            }
        }
    }

    /// Try to verify a bcrypt hash directly (special case for bcrypt).
    /// For other algorithms, use hash_hex for comparison.
    pub fn verify_bcrypt(hash: &str, input: &[u8]) -> bool {
        bcrypt::verify(input, hash).unwrap_or_default()
    }

    /// Length in hex characters of a digest produced by this algorithm.
    /// Bcrypt hashes are ~60 characters.
    pub fn hex_len(self) -> usize {
        match self {
            Algorithm::Md5 => 32,
            Algorithm::Sha1 => 40,
            Algorithm::Sha256 => 64,
            Algorithm::Sha512 => 128,
            Algorithm::Bcrypt => 60,
        }
    }

    /// Best-effort guess of the algorithm from the length of a hex digest.
    ///
    /// Returns `None` if the length does not match any supported algorithm.
    /// Note that MD5 and NTLM share a length; here a 32-char digest is
    /// assumed to be MD5. Bcrypt hashes are detected by the "$2" prefix.
    pub fn guess_from_hex(digest: &str) -> Option<Algorithm> {
        let trimmed = digest.trim();

        // Bcrypt detection: starts with $2a$, $2b$, $2x$, or $2y$
        if trimmed.starts_with("$2a$")
            || trimmed.starts_with("$2b$")
            || trimmed.starts_with("$2x$")
            || trimmed.starts_with("$2y$")
        {
            return Some(Algorithm::Bcrypt);
        }

        match trimmed.len() {
            32 => Some(Algorithm::Md5),
            40 => Some(Algorithm::Sha1),
            64 => Some(Algorithm::Sha256),
            128 => Some(Algorithm::Sha512),
            _ => None,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Algorithm::Md5 => "md5",
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
            Algorithm::Bcrypt => "bcrypt",
        };
        f.write_str(s)
    }
}

impl FromStr for Algorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "md5" => Ok(Algorithm::Md5),
            "sha1" | "sha-1" => Ok(Algorithm::Sha1),
            "sha256" | "sha-256" => Ok(Algorithm::Sha256),
            "sha512" | "sha-512" => Ok(Algorithm::Sha512),
            "bcrypt" => Ok(Algorithm::Bcrypt),
            other => Err(format!(
                "unknown algorithm '{other}' (expected: md5, sha1, sha256, sha512, bcrypt)"
            )),
        }
    }
}
