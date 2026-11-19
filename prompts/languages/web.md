# HTML specifics
- Inline scripts that read `location`, `document.URL`, `location.hash` or query parameters into `innerHTML`/`document.write` (DOM XSS).
- Forms posting credentials over `http://`; missing `rel="noopener"` on `target="_blank"` to untrusted sites; third-party scripts without Subresource Integrity.
- Secrets, internal URLs or tokens embedded in pages.
