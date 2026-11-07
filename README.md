# RustHashTool

A Rust command-line tool for testing password hashes against a wordlist, with parallel CPU processing and support for MD5, SHA-1, SHA-256, SHA-512, and bcrypt.

Built for learning and authorized password auditing. Supply your own candidate wordlist and target hashes; matching entries are printed as `hash:plaintext`.

## Features

- Parallel wordlist processing with Rayon and an optional thread limit.
- Automatic algorithm selection from digest length or bcrypt prefix.
- Multiple targets from command-line arguments, a hash file, or both.
- Salted MD5 and SHA-family hashes using `hash:salt` input and `salt + password` hashing.
- Raw-byte wordlist input, including non-UTF-8 entries and Windows line endings.
- Results on standard output; run statistics and errors on standard error.

## Getting started

Install the Rust toolchain, including Cargo, then run these commands from the directory containing `Cargo.toml`:

```sh
cargo build --release
cargo run --release -- --help
```

The compiled executable is `target/release/rusthashtool` on Linux/macOS or `target/release/rusthashtool.exe` on Windows. Examples below use `cargo run` so they work without adding the executable to your PATH.

Try the included sample wordlist:

```sh
cargo run --release -- -w examples/wordlist.txt -H 5f4dcc3b5aa765d61d8327deb882cf99
```

Expected standard output:

```text
5f4dcc3b5aa765d61d8327deb882cf99:password
```

## Usage

```text
rusthashtool -w <FILE> [-H <HASH> ...] [-f <FILE>] [-m <ALGO>] [-t <N>] [-v]
```

At least one target is required through `--hash` or `--hash-file`.

| Option | Description |
| --- | --- |
| `-w, --wordlist <FILE>` | Required candidate file, one password per line. |
| `-H, --hash <HASH>` | Target hash; repeat this option for multiple targets. |
| `-f, --hash-file <FILE>` | UTF-8 target file, one hash per line. Blank lines and lines beginning with `#` are ignored. |
| `-m, --mode <ALGO>` | `md5`, `sha1`, `sha256`, `sha512`, or `bcrypt`. Automatically selected when omitted. |
| `-t, --threads <N>` | Positive worker count; defaults to Rayon's default pool size. |
| `-v, --verbose` | Accepted by the CLI; currently does not change output. |
| `-h, --help` | Show help. |
| `-V, --version` | Show version. |

### Multiple hashes

```sh
cargo run --release -- -w examples/wordlist.txt -f examples/hashes_md5.txt
cargo run --release -- -w examples/wordlist.txt -f examples/hashes_sha256.txt -m sha256 -t 4
```

Use one algorithm per run. For hexadecimal digests, automatic selection maps 32, 40, 64, and 128 characters to MD5, SHA-1, SHA-256, and SHA-512 respectively. Length alone does not identify every possible hash format; NTLM is not supported.

### Salted hashes

Use `digest:salt`, either as a quoted argument or as a line in the target file. For MD5 and SHA-family targets the implementation computes:

```text
digest = algorithm(salt_bytes + password_bytes)
```

The salt is literal text, not decoded hexadecimal or Base64. Password-before-salt and other salt schemes are not supported.

### Bcrypt

Put bcrypt targets in a hash file and run:

```sh
cargo run --release -- -w examples/wordlist.txt -f bcrypt_hashes.txt -m bcrypt
```

Bcrypt embeds its salt and cost in the target string. Candidates are verified against that string. Using a file also avoids shell expansion of `$` characters. Actual bcrypt format support follows the `bcrypt` dependency; the CLI's prefix check alone does not fully validate a target.

### Save results

```sh
cargo run --release -- -w examples/wordlist.txt -f examples/hashes_md5.txt > recovered.txt
```

Standard output contains matches only. The banner and summary are written to standard error. Salt values are not included in result lines.

| Exit code | Meaning |
| --- | --- |
| `0` | All targets recovered. |
| `1` | Search finished with unrecovered targets. |
| `2` | Invalid arguments or a run error. |

## How it works

The tool loads the entire wordlist into memory and splits it into candidate byte slices for parallel processing. Unsalted MD5 and SHA-family candidates are hashed once and looked up in a target set. Salted targets require additional hashing; bcrypt requires verification against each target until a match is found.

The search processes the full wordlist even if targets have already been recovered. Empty candidates are skipped. Non-UTF-8 candidates are hashed as their original bytes, but recovered output uses replacement characters for invalid UTF-8 and is therefore not a byte-perfect export.

## Scope and current limitations

- CPU only; no GPU acceleration, masks, brute-force generation, or mutation rules.
- Memory use grows with the size of the wordlist.
- A candidate produces at most one match per pass, so targets sharing a plaintext across different salts or bcrypt hashes can be underreported.
- Results are deduplicated by digest, without salt as part of their identity.
- Invalid bcrypt targets can appear as unrecovered rather than produce a validation error.
- Reported throughput counts candidates per second, even though the summary labels it `H/s`; it is not a comparable hash-operation benchmark across algorithms.

## Project layout

```text
src/main.rs             CLI, input validation, and reporting
src/hash.rs             Algorithms, digest computation, and bcrypt verification
src/cracker.rs          Parallel wordlist search
examples/               Sample candidates and MD5/SHA-256 target files
```

## Development

```sh
cargo check
cargo test
```

The project currently has no automated test cases. Contributions should include a small reproducible example and describe the expected result.
