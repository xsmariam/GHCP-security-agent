# C / C++ / Objective-C specifics
- Memory safety: buffer overflows via `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")`, `memcpy` with unchecked lengths (CWE-120, 121, 122, 787); off-by-one; out-of-bounds reads (CWE-125).
- Format strings: `printf(user)`, `syslog(prio, user)` (CWE-134).
- Integer issues: overflow/underflow in size calculations before `malloc`/indexing (CWE-190, 191); signed/unsigned confusion.
- Lifetime: use-after-free (CWE-416), double free (CWE-415), NULL dereference (CWE-476), uninitialized memory (CWE-457/908).
- Commands/files: `system`, `popen` with input; TOCTOU between `access`/`stat` and `open` (CWE-367); `tmpnam`/`mktemp` (CWE-377).
- Randomness/crypto: `rand()` for secrets, disabled certificate verification in OpenSSL/curl (`CURLOPT_SSL_VERIFYPEER 0`).
- Cite the exact allocation/copy line; explain the attacker-controlled length or index.
