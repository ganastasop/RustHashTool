//! rusthashtool — a small hashcat-like wordlist password cracker.
//!
//! Give it a wordlist and one or more target hashes; it hashes every word in
//! parallel and reports which plaintexts match. Algorithm is auto-detected
//! from the digest length or bcrypt prefix unless you pass `-m/--mode`.

mod cracker;
mod hash;

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::Parser;

use cracker::Target;
use hash::Algorithm;

/// A hashcat-like wordlist cracker for MD5 / SHA-1 / SHA-256 / SHA-512 / Bcrypt.
#[derive(Parser, Debug)]
#[command(name = "rusthashtool", version, about, long_about = None)]
struct Cli {
    /// Path to the wordlist file (one candidate per line).
    #[arg(short = 'w', long = "wordlist", value_name = "FILE")]
    wordlist: PathBuf,

    /// A single target hash (hex or bcrypt). Repeat the flag for multiple hashes.
    #[arg(short = 'H', long = "hash", value_name = "HEX")]
    hash: Vec<String>,

    /// File containing target hashes, one per line.
    #[arg(short = 'f', long = "hash-file", value_name = "FILE")]
    hash_file: Option<PathBuf>,

    /// Hash algorithm: md5, sha1, sha256, sha512, bcrypt. Auto-detected if omitted.
    #[arg(short = 'm', long = "mode", value_name = "ALGO")]
    mode: Option<Algorithm>,

    /// Number of worker threads (defaults to all logical cores).
    #[arg(short = 't', long = "threads", value_name = "N")]
    threads: Option<usize>,

    /// Print progress details (per-hash lines and timing).
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(all_cracked) => {
            if all_cracked {
                ExitCode::SUCCESS
            } else {
                // Mirror hashcat: exhausted without cracking everything -> nonzero.
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<bool, String> {
    // Configure the global rayon thread pool if a count was requested.
    if let Some(n) = cli.threads {
        if n == 0 {
            return Err("--threads must be at least 1".into());
        }
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .map_err(|e| format!("failed to set thread count: {e}"))?;
    }

    // Collect target hashes from --hash flags and/or --hash-file.
    let mut targets: Vec<Target> = Vec::new();
    for h in &cli.hash {
        targets.push(parse_target_hash(h)?);
    }
    if let Some(path) = &cli.hash_file {
        let contents = fs::read_to_string(path)
            .map_err(|e| format!("could not read hash file {}: {e}", path.display()))?;

        for line in contents.lines() {
            let input = line.trim();
            if input.is_empty() || input.starts_with('#') {
                continue;
            }
            targets.push(parse_target_hash(input)?);
        }
    }

    if targets.is_empty() {
        return Err("no target hashes given (use --hash or --hash-file)".into());
    }

    // Dedupe while preserving order.
    targets.dedup();

    // Resolve the algorithm: explicit mode wins, otherwise guess from length
    // and require every target to agree.
    let algo = resolve_algorithm(cli.mode, &targets)?;

    // Sanity check: validate hashes based on algorithm.
    for t in &targets {
        // Skip hex validation for bcrypt; bcrypt hashes have a specific format ($2a$, $2b$, etc.)
        if algo != Algorithm::Bcrypt {
            if t.digest.len() != algo.hex_len() {
                return Err(format!(
                    "hash '{}' is {} hex chars but {algo} expects {}",
                    t.digest,
                    t.digest.len(),
                    algo.hex_len()
                ));
            }

            if !t.digest.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("hash '{}' contains non-hex characters", t.digest));
            }
        } else {
            // For bcrypt, just verify it has a valid prefix
            if !t.digest.starts_with("$2a$")
                && !t.digest.starts_with("$2b$")
                && !t.digest.starts_with("$2x$")
                && !t.digest.starts_with("$2y$")
            {
                return Err(format!(
                    "hash '{}' does not appear to be a valid bcrypt hash (should start with $2a$, $2b$, $2x$, or $2y$)",
                    t.digest
                ));
            }
        }
    }

    // Load the wordlist as raw bytes. Real wordlists (e.g. rockyou.txt) are
    // not valid UTF-8, so we never try to decode the whole thing.
    let buffer = fs::read(&cli.wordlist)
        .map_err(|e| format!("could not read wordlist {}: {e}", cli.wordlist.display()))?;

    if buffer.is_empty() {
        return Err("wordlist is empty".into());
    }

    // Quick single pass just to show a candidate count in the banner.
    let approx_words = buffer.iter().filter(|&&b| b == b'\n').count() + 1;

    eprintln!(
        "rusthashtool: {algo} | {} target(s) | ~{} words | {} threads",
        targets.len(),
        approx_words,
        rayon::current_num_threads(),
    );

    let start = Instant::now();
    let report = cracker::crack(algo, &targets, &buffer);
    let elapsed = start.elapsed();

    // Report results to stdout so they can be piped; diagnostics go to stderr.
    for c in &report.cracked {
        println!("{}:{}", c.digest, c.plaintext);
    }

    let rate = if elapsed.as_secs_f64() > 0.0 {
        report.words_tried as f64 / elapsed.as_secs_f64()
    } else {
        report.words_tried as f64
    };
    eprintln!(
        "recovered {}/{} in {:.2?} ({:.0} H/s)",
        report.cracked.len(),
        targets.len(),
        elapsed,
        rate,
    );

    Ok(report.uncracked.is_empty())
}

/// Parse a hash string into a Target, handling both bcrypt and salted hex formats.
///
/// For bcrypt: `$2a$12$...` (no salt splitting; bcrypt embeds salt internally)
/// For hex with salt: `hash:salt` (splits on first `:`)
/// For plain hex: `hash` (no salt)
fn parse_target_hash(input: &str) -> Result<Target, String> {
    let input = input.trim();

    // Bcrypt hashes start with $2a$, $2b$, $2x$, or $2y$ and should NOT be split on ':'
    // because the ':' character may appear in the base64-encoded portion.
    if input.starts_with("$2a$")
        || input.starts_with("$2b$")
        || input.starts_with("$2x$")
        || input.starts_with("$2y$")
    {
        return Ok(Target {
            digest: input.to_string(),
            salt: None,
        });
    }

    // For other formats, support hash:salt notation
    if let Some((hash, salt)) = input.split_once(':') {
        Ok(Target {
            digest: normalize_hash(hash),
            salt: Some(salt.as_bytes().to_vec()),
        })
    } else {
        Ok(Target {
            digest: normalize_hash(input),
            salt: None,
        })
    }
}

/// Normalize a hash for consistent comparison.
/// For hex hashes, lowercase and strip whitespace.
fn normalize_hash(h: &str) -> String {
    h.trim().to_ascii_lowercase()
}

/// Decide which algorithm to use, validating agreement across targets.
fn resolve_algorithm(mode: Option<Algorithm>, targets: &[Target]) -> Result<Algorithm, String> {
    if let Some(m) = mode {
        return Ok(m);
    }
    let first = targets
        .first()
        .and_then(|t| Algorithm::guess_from_hex(&t.digest))
        .ok_or_else(|| {
            "could not auto-detect algorithm from hash length; pass --mode".to_string()
        })?;
    for t in targets {
        match Algorithm::guess_from_hex(&t.digest) {
            Some(a) if a == first => {}
            _ => return Err(
                "target hashes have mixed lengths/formats; run one algorithm at a time with --mode"
                    .to_string(),
            ),
        }
    }
    Ok(first)
}
