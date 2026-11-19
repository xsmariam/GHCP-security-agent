# PHP specifics
- SQL: `mysqli_query`/`$pdo->query` with variables interpolated (safe: prepared statements with bound params).
- Commands/code: `exec`, `system`, `shell_exec`, `passthru`, backticks, `popen`, `proc_open`, `eval`, `assert` with strings, `preg_replace` with `/e`, `create_function`.
- Inclusion: `include`/`require` with user input (LFI/RFI), `allow_url_include`.
- Deserialization: `unserialize` on user data (use `json_decode`), `phar://` wrappers on file functions.
- XSS: `echo $_GET[...]` without `htmlspecialchars(..., ENT_QUOTES)`; templates with raw output (`{!! !!}` in Blade, `|raw` in Twig).
- Auth/sessions: `md5`/`sha1` passwords (use `password_hash`), `==` loose comparison of hashes/tokens (use `hash_equals`), `rand`/`mt_rand` for tokens (use `random_bytes`), missing `session_regenerate_id` after login.
- Files: `$_FILES` uploads saved with user names/extensions into web root; `file_get_contents($userUrl)` (SSRF).
