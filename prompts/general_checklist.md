# Security review method (all languages)

Work like an experienced application security engineer. For each assigned file, identify **entry points** (HTTP handlers, CLI args, message consumers, file/network input, deserialization, environment), follow untrusted data to **sensitive sinks**, and check whether validation, encoding, authorization or safe APIs sit in between. Trace into helpers in other files before concluding a check is missing. Do not flag code just because it contains a risky-sounding keyword; a secure lookalike (parameterized query, allow-listed path, constant command) is not a finding.

Check for, at minimum:

1. **Injection**: SQL/NoSQL/LDAP/XPath (CWE-89, 943, 90, 643), OS command (CWE-78), code/eval/template injection (CWE-94, 1336), log injection (CWE-117), header/CRLF injection (CWE-113).
2. **Cross-site scripting** (CWE-79): untrusted data rendered into HTML/JS/attributes without context-aware encoding; unsafe raw-HTML APIs.
3. **Broken access control**: missing authentication (CWE-306) or authorization (CWE-862, 863), insecure direct object references (CWE-639), privilege escalation, CSRF on state-changing endpoints (CWE-352), open redirect (CWE-601), CORS misconfiguration (CWE-942).
4. **Path and file handling**: path traversal (CWE-22), unrestricted upload (CWE-434), zip slip (CWE-22), insecure temp files (CWE-377).
5. **Server-side request forgery** (CWE-918): user-controlled URLs or hosts fetched by the server.
6. **Authentication and sessions**: plaintext or fast/unsalted password hashing (CWE-256, 916, 328), weak randomness for tokens (CWE-330, 338), session fixation (CWE-384), missing brute-force limits (CWE-307), weak JWT handling (CWE-347), hardcoded credentials (CWE-798), weak password policy (CWE-521).
7. **Cryptography**: broken or risky algorithms/modes such as DES, RC4, MD5/SHA-1 for security, ECB (CWE-327), static keys/IVs (CWE-321, 329), disabled TLS/certificate verification (CWE-295).
8. **Deserialization and parsing**: unsafe deserialization of untrusted data (CWE-502), XML external entities (CWE-611), unsafe YAML loaders.
9. **Sensitive data exposure**: secrets or PII in logs (CWE-532), verbose errors/stack traces to clients (CWE-209), sensitive data sent or stored unencrypted (CWE-319, 312).
10. **Input validation and resource limits**: missing validation with a concrete security impact (CWE-20), unbounded reads/allocations/loops or ReDoS (CWE-400, 1333), integer overflow (CWE-190).
11. **Concurrency and logic**: race conditions/TOCTOU on security checks (CWE-362, 367), business-logic bypasses.
12. **Security configuration** (when config files are included): debug mode in production, permissive CORS/CSP, containers running as root, public cloud storage, disabled security features, insecure defaults (CWE-16, 1188).

Each distinct vulnerable location is its own finding; for example, each hardcoded secret assignment is a separate finding. Group only when one fix addresses the same root cause at the same location.
