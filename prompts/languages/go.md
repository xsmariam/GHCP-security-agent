# Go specifics
- SQL: `fmt.Sprintf` or `+` building queries for `db.Query`/`Exec` (safe: `?`/`$1` placeholders); GORM `Raw`/`Where` with string concatenation.
- Commands: `exec.Command("sh", "-c", input)` or user-controlled program names.
- Templates: `text/template` used for HTML (no escaping), `template.HTML(userInput)`.
- Files: `filepath.Join(base, userInput)` without checking the cleaned result stays under base; archive extraction (zip slip); `http.ServeFile` with user paths.
- SSRF: `http.Get(userURL)`; TLS: `InsecureSkipVerify: true`.
- Crypto/random: `math/rand` for secrets (use `crypto/rand`), MD5/SHA-1 for passwords (use bcrypt/argon2).
- Concurrency: data races on shared maps/slices in handlers; unchecked errors on security-relevant calls; unbounded `io.ReadAll(r.Body)` (use `http.MaxBytesReader`).
