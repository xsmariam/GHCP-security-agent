# Swift / iOS specifics
- Secrets in source or `Info.plist`; sensitive data in `UserDefaults` instead of Keychain (CWE-312).
- `NSAllowsArbitraryLoads`/ATS exceptions; `URLSessionDelegate` that trusts any certificate (CWE-295).
- `WKWebView`/`UIWebView` loading untrusted HTML or enabling JS bridges with untrusted content; `evaluateJavaScript` with input.
- SQL via `sqlite3_exec` with interpolated strings; `NSKeyedUnarchiver` without secure coding (CWE-502).
- URL scheme / universal link handlers acting on parameters without validation.
