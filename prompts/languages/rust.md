# Rust specifics
- `unsafe` blocks: raw pointer arithmetic, `from_raw_parts` with unchecked lengths, `transmute`, `get_unchecked`, FFI boundaries.
- SQL: `format!` building queries for `sqlx::query`/diesel `sql_query` (safe: bind parameters / `query!`).
- Commands: `Command::new("sh").arg("-c").arg(input)`.
- Panics as DoS: `unwrap`/`expect`/indexing on attacker-controlled input in request handlers; unbounded body reads.
- Paths: `Path::join` with absolute user input replaces the base; archive extraction.
- TLS: `danger_accept_invalid_certs(true)`; randomness: non-cryptographic RNGs for secrets.
